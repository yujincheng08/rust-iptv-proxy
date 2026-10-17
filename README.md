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
Append `--features rustls` if TLS support is needed in a fully static binary.

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

Release builds also include `x86_64-openwrt-openssl.zip`. This variant is built
with the OpenWrt 24.10.2 SDK and dynamically links OpenSSL 3 to keep the binary
small. Install the runtime dependencies before using it:

```bash
opkg update
opkg install libopenssl3 ca-bundle
```

The binary expects `libssl.so.3`, `libcrypto.so.3`, `libgcc_s.so.1`, and musl's
dynamic loader to be available on the router.

### Docker

#### RUN
Use `docker run`:

```bash
docker run -d \
  --name iptv-proxy \
  -p 7878:7878 \
  rust-iptv-proxy:latest \
  --user "account" \
  --passwd "password" \
  --mac "mac" \
  --udp-proxy
```
#### Compose (recommended)
example docker-compose.yml:

```YAML
services:
  iptv-proxy:
    image: rust-iptv-proxy:latest
    container_name: iptv-proxy
    ports:
      - "7878:7878"
    command: >
      --user "${IPTV_USER}"
      --passwd "${IPTV_PASS}"
      --mac "${IPTV_MAC}"
      --udp-proxy
    restart: always
```
Note: use `.env` to store environmental variables.

