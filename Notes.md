# Notes

## To conigure MG3

```bash
curl -d '{"action": "SetConfig", "mqtt": {"mqtt_url": "mqtts://$serverHost:8833", "username": "moko_device", "password": "secret"}, "common": {"protocol": "mqtt", "rssi": -99}, "other": {"timezone": "UTC"}}' http://$remoteIp/set

curl -d '{"action": "reboot"}' http://192.168.1.19/set
```

## To verify MG3

```bash
 curl -d '{"action": "getConfig"}' http://192.168.1.19/set | jq
```

Should equal (ignoring extra keys)

```json
{
  "mqtt": {
    "keepalive": 120,
    "qos": 0,
    "mqtt_url": "mqtts://$serverHost:8833",
    "publish_topic": "/mg3/$macLower/status",
    "subscribe_topic": "/mg3/$macLower/action",
    "response_topic": "/mg3/$macLower/response",
    "username": "moko_device",
    "password": "secret",
    "use_ssl": 0
  },
  "scan": {
    "itvl": 100,
    "window": 100,
    "passive": 1,
    "filter_duplicates": 0
  },
  "common": {
    "protocol": "mqtt",
    "upload_interval": 1,
    "rssi": 0,
    "regex_mac": "",
    "regex_raw": "",
    "mac_list": ""
  },
  "other": {
    "led_on": 1,
    "timeserver": "cn.pool.ntp.org",
    "timezone": "UTC"
  },
  "code": 200,
  "message": "Action GetConfig succeed!"
}
```
