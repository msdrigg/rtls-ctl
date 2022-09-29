use std::{fmt::Display, net::Ipv4Addr, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct Mac {
    pub bytes: [u8; 6],
}

impl Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = hex::encode_upper(&self.bytes);
        let mut result = String::with_capacity(3 * 6);

        for (idx, char) in encoded.chars().enumerate() {
            result.push(char);
            if idx % 2 != 0 {
                result.push(':');
            }
        }
        result.pop();

        write!(f, "{}", result)
    }
}
impl FromStr for Mac {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let no_colons = s.replace(':', "");
        let mut slice = [0u8; 6];
        hex::decode_to_slice(&no_colons, &mut slice)?;
        Ok(Self { bytes: slice })
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mac")
            .field("bytes", &self.to_string())
            .finish()
    }
}

impl Serialize for Mac {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Mac {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let deserialized: &str = <&str>::deserialize(deserializer)?;
        Self::from_str(deserialized).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Serialize)]
pub enum GatewayType {
    G1,
    MG3,
}

#[derive(Debug, Serialize)]
pub struct GatewayDetection {
    pub ip: Ipv4Addr,
    pub gateway: GatewayType,
    pub mac: Mac,
}
