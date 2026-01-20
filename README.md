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

- `/playlist`: m3u8 list
- `/xmltv`: EGP

### Docker

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


### Example init.d

```sh
#!/bin/sh /etc/rc.common

START=99
STOP=99

MAC=
USER=
PASSWD=
INTERFACE=pppoe-iptv
BIND=0.0.0.0:7878

start() {
        ( RUST_LOG=info /usr/bin/iptv -u $USER -p $PASSWD -m $MAC -b $BIND -I $INTERFACE --udp-proxy --rtsp-proxy 2>&1 & echo $! >&3 ) 3>/var/run/iptv.pid | logger -t "iptv-proxy" &
}

stop() {
        if [ -f /var/run/iptv.pid ]; then
                kill -9 $(cat /var/run/iptv.pid) 2>/dev/null
                rm -f /var/run/iptv.pid
        fi
}
```

### Build for openwrt
You don't need to install openwrt sdk for this.
```bash
rustup target add x86_64-unknown-linux-musl
cargo build -r --target x86_64-unknown-linux-musl
```
Append `--features rustls-tls` if need tls support.

To reduce binary size, you need to install openwrt sdk to ${openwrt}, and then build with
```bash
rustup +nightly target add x86_64-unknown-linux-musl
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
toolchain="$(ls -d ${openwrt}/staging_dir/toolchain-*)"
export RUSTFLAGS="-Ctarget-feature=-crt-static -Zlocation-detail=none -Zunstable-options -Cpanic=immediate-abort -Clinker=$(ls ${toolchain}/bin/*-openwrt-linux-gcc)"
cargo +nightly build -Zbuild-std=std,panic_abort -r --target x86_64-unknown-linux-musl
```

#### Build with openssl for openwrt
You need to install openwrt sdk to ${openwrt}, and then prepare:
```bash
cd ${openwrt}
./scripts/feeds update
./scripts/feeds install openssl
make V=s -j$(nproc)
```
Then build with
```bash
rustup target add x86_64-unknown-linux-musl
export PKG_CONFIG_SYSROOT_DIR=$(ls -d ${openwrt}/staging_dir/target-*)
export PKG_CONFIG_PATH=$PKG_CONFIG_SYSROOT_DIR/usr/lib/pkgconfig
toolchain="$(ls -d ${openwrt}/staging_dir/toolchain-*)"
export TARGET_CC=$(ls ${toolchain}/bin/*-openwrt-linux-gcc)
export STAGING_DIR=$PKG_CONFIG_SYSROOT_DIR
export RUSTFLAGS="-C target-feature=-crt-static -Zlocation-detail=none -C linker=$(ls ${toolchain}/bin/*-openwrt-linux-gcc)"
cargo build -r --target x86_64-unknown-linux-musl --features tls
```