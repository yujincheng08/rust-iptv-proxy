### Usage
```
Usage: iptv [OPTIONS] --user <USER> --passwd <PASSWD> --mac <MAC>

Options:
  -u, --user <USER>                      Login username
  -p, --passwd <PASSWD>                  Login password
  -m, --mac <MAC>                        MAC address
  -i, --imei <IMEI>                      IMEI [default: ]
  -b, --bind <BIND>                      Bind address:port [default: 127.0.0.1:7878]
  -a, --address <ADDRESS>                IP address/interface name [default: ]
  -I, --interface <INTERFACE>            Interface to request
      --extra-playlist <EXTRA_PLAYLIST>  Url to extra m3u
      --extra-xmltv <EXTRA_XMLTV>        Url to extra xmltv
      --udp-proxy                        Use UDP proxy
      --rtsp-proxy                       Use rtsp proxy
  -h, --help                             Print help
```

### Endpoints

- `127.0.0.1:7878/playlist`: m3u8 list
- `127.0.0.1:7878/xmltv`: EGP

方式 A：RUN传入参数
这是最直接的方式，追加在镜像名后的内容会自动拼接到 iptv 后面。
```
docker run -d \
  --name iptv-proxy \
  -p 7878:7878 \
  ghcr.io/mjl371/rust-iptv-proxy:latest \
  --user "你的账号" \
  --passwd "你的密码" \
  --mac "你的MAC地址" \
  --udp-proxy
```
方式 B：Docker Compose（推荐）
如果你希望在 docker-compose.yml 中管理，可以利用环境变量来传参：
YAML
```
services:
  iptv-proxy:
    image: ghcr.io/mjl371/rust-iptv-proxy:latest
    container_name: iptv-proxy
    ports:
      - "7878:7878"
    # 使用 command 覆盖默认的 CMD
    command: >
      --user "${IPTV_USER}"
      --passwd "${IPTV_PASS}"
      --mac "${IPTV_MAC}"
      --udp-proxy
    restart: always
```
注：你可以在目录下创建一个 .env 文件存放 IPTV_USER 等敏感信息。
