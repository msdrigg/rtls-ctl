use anyhow::Context;
use clap::Parser;
use log::info;
use rtls_ctl::types::{GatewayDetection, GatewayType, Mac};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::str::FromStr;
use std::{net::Ipv4Addr, ops::Range, time::Duration};
use tokio::{net::TcpStream, time::timeout};

use futures::StreamExt;
use futures::TryFutureExt;

struct RangeWrapper {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

struct RangeWrapperIter {
    range: Range<u32>,
}

impl Iterator for RangeWrapperIter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|n| Ipv4Addr::from(n))
    }
}

impl IntoIterator for RangeWrapper {
    type Item = Ipv4Addr;

    type IntoIter = RangeWrapperIter;

    fn into_iter(self) -> Self::IntoIter {
        RangeWrapperIter {
            range: Range {
                start: u32::from(self.start),
                end: u32::from(self.end),
            },
        }
    }
}

const CONCURRENCY: usize = 512;
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct ScanArgs {
    /// Name of the person to greet
    #[arg(
        help = "Ip range to scan (e.g. 192.168.1.1..192.168.1.20). Default will be chosen based on local ip."
    )]
    range: Option<String>,
    #[arg(short, long, default_value_t = CONCURRENCY)]
    concurrency: usize,
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = ScanArgs::parse();

    env_logger::builder()
        .parse_default_env()
        .filter_level(match args.verbose {
            0 => log::LevelFilter::Warn,
            1 => log::LevelFilter::Info,
            2 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .init();

    let (start, end): (Ipv4Addr, Ipv4Addr) = match args.range {
        Some(s) => {
            let (s1, s2) = s
                .split_once("..")
                .context("Range argument must contain '..'")?;
            (
                s1.parse().context(
                    "Error parsing start ip address. Expected ip v4 address like '192.168.1.1'",
                )?,
                s2.parse().context(
                    "Error parsing end ip address. Expected ip v4 address like '192.168.1.2'",
                )?,
            )
        }
        None => match local_ip_address::local_ip().context("Error getting local ip address")? {
            IpAddr::V4(ip) => (
                Ipv4Addr::new(ip.octets()[0], ip.octets()[1], ip.octets()[2], 1),
                Ipv4Addr::new(ip.octets()[0], ip.octets()[1], ip.octets()[2], 255),
            ),
            IpAddr::V6(_) => {
                anyhow::bail!(
                    "Cannot extract a local ipv4 address. Please specify start and end ip range"
                )
            }
        },
    };

    info!("Scanning range {}..{}...", start, end);

    let results: Vec<GatewayDetection> = futures::stream::iter(RangeWrapper { start, end })
        .map(|ip| filter_addr(ip))
        .buffer_unordered(args.concurrency)
        .filter_map(|v| async move {
            if let Err(err) = &v {
                log::trace!("Error: {}", err);
            }
            v.ok()
        })
        .collect()
        .await;
    info!("Scan ended finding {} gateways", results.len());

    println!(
        "{}",
        serde_json::to_string_pretty(&results).expect("Gateways must be serializable"),
    );

    Ok(())
}

async fn filter_addr(ip: Ipv4Addr) -> anyhow::Result<GatewayDetection> {
    filter_addr_tcp(ip)
        .await
        .ok()
        .context(format!("Error getting tcp connection to {}", ip))?;

    tokio::select! {
        res = filter_addr_g1(ip).or_else(|_| futures::future::pending()) => {
                res
        }
        res = filter_addr_mg3(ip).or_else(|_| futures::future::pending()) => {
            res
        }
        _ = tokio::time::sleep(TIMEOUT) => {
            Err(anyhow::anyhow!("Timeout trying to get gateway response"))
        }
    }
}

async fn filter_addr_tcp(ip: Ipv4Addr) -> anyhow::Result<()> {
    timeout(TIMEOUT, TcpStream::connect((ip, 80))).await??;
    Ok(())
}

async fn filter_addr_g1(ip: Ipv4Addr) -> anyhow::Result<GatewayDetection> {
    let response: Value = reqwest::Client::new()
        .post(format!("http://{}/cgi-bin/cgic-statusget", ip))
        .header("Authorization", "Basic YWRtaW46")
        .json(&json! {{
            "header": {
                "version": 1,
            },
        }})
        .send()
        .await?
        .json()
        .await?;

    if response["header"]["code"] == json!(200) {
        Ok(GatewayDetection {
            ip,
            gateway: GatewayType::G1,
            mac: Mac::from_str(
                &response["body"]["gateway"]["status"]["mac"]
                    .as_str()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Error parsing mac address from response {:?}", response)
                    })?,
            )?,
        })
    } else {
        Err(anyhow::anyhow!(
            "Error mac not found in response {:?}",
            response
        ))
    }
}

async fn filter_addr_mg3(ip: Ipv4Addr) -> anyhow::Result<GatewayDetection> {
    let response: Value = reqwest::get(format!("http://{}/hello", ip))
        .await?
        .json()
        .await?;

    if let Some(mac) = response["mac"].as_str() {
        Ok(GatewayDetection {
            ip,
            gateway: GatewayType::MG3,
            mac: Mac::from_str(mac).context(format!(
                "Error parsing mac address from response {:?}",
                response
            ))?,
        })
    } else {
        Err(anyhow::anyhow!(
            "Error mac not found in response {:?}",
            response
        ))
    }
}
