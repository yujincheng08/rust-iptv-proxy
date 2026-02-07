### Usage
```
Usage: iptv [OPTIONS] --user <USER> --passwd <PASSWD> --mac <MAC>

Options:
  -u, --user <USER>                      Login username (or config [app].user)
  -p, --passwd <PASSWD>                  Login password (or config [app].passwd)
  -m, --mac <MAC>                        MAC address (or config [app].mac)
  -i, --imei <IMEI>                      IMEI (or config [app].imei) [default: ]
  -b, --bind <BIND>                      Bind address:port (or config [app].bind) [default: 0.0.0.0:7878]
  -a, --address <ADDRESS>                IP address/interface name (or config [app].address) [default: ]
  -I, --interface <INTERFACE>            Interface to request (or config [app].interface)
  -c, --config <CONFIG>                  Config file path (TOML)
      --extra-playlist <EXTRA_PLAYLIST>  Url to extra m3u
      --extra-xmltv <EXTRA_XMLTV>        Url to extra xmltv
      --udp-proxy                        Use UDP proxy
      --rtsp-proxy                       Use rtsp proxy
  -h, --help                             Print help
```

### Config file (TOML)
You can put most settings into a config file and pass it via `-c/--config`.

Key features in config:
- Channel alias rules (`[alias]` + `[[alias.rules]]`), supports map and regex rules, with `first_match` or `chain` mode.
- Playlist rendering templates (`[template]`), customize `#EXTINF` and URL lines.
- Token-based protection (`[auth]`) for endpoints.
- Management endpoints switch (`[manage]`).
- XMLTV alias naming (`[xmltv]`).

Example: `config/iptv.toml` (see full file in repo).

### Endpoints

- `/playlist`: m3u8 list (with alias/group/sort/template)
- `/xmltv`: EPG
- `/status`: system/status page (uptime, counts, config info)
- `/manage`: management dashboard
- `/manage/config`: view current config (token redacted)
- `/manage/reload`: reload config and templates
- `/manage/test?name=...`: test alias/group/resolution
- `/manage/channels`: channels JSON
- `/manage/channels/html`: channels UI

### Token protection
If `auth.token` is set and the endpoint is in `auth.protect`, provide token by:
- Header: `Authorization: Bearer <TOKEN>`
- Header: `X-Api-Token: <TOKEN>`
- Query: `?token=<TOKEN>`

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
        ( RUST_LOG=info /usr/bin/iptv -c /etc/iptv/iptv.toml -b $BIND -I $INTERFACE --udp-proxy --rtsp-proxy 2>&1 & echo $! >&3 ) 3>/var/run/iptv.pid | logger -t "iptv-proxy" &
}

stop() {
        if [ -f /var/run/iptv.pid ]; then
                kill -9 $(cat /var/run/iptv.pid) 2>/dev/null
                rm -f /var/run/iptv.pid
        fi
}
```

### Build
Native build:
```bash
cargo build -r
```

Cross build (same toolchain as CI, no OpenWrt SDK required):
```bash
cargo install cargo-cross
cargo cross build -r --target x86_64-unknown-linux-musl
```

TLS features:
- `--features rustls` for Rustls (no system OpenSSL).
- `--features tls` for OpenSSL (requires OpenWrt SDK toolchain and libs).

#### OpenWrt + OpenSSL (optional)
If you need OpenSSL on OpenWrt, install the SDK to `${openwrt}` and build with:
```bash
cd ${openwrt}
./scripts/feeds update
./scripts/feeds install openssl
make V=s -j$(nproc)

rustup target add x86_64-unknown-linux-musl
export PKG_CONFIG_SYSROOT_DIR=$(ls -d ${openwrt}/staging_dir/target-*)
export PKG_CONFIG_PATH=$PKG_CONFIG_SYSROOT_DIR/usr/lib/pkgconfig
toolchain="$(ls -d ${openwrt}/staging_dir/toolchain-*)"
export TARGET_CC=$(ls ${toolchain}/bin/*-openwrt-linux-gcc)
export STAGING_DIR=$PKG_CONFIG_SYSROOT_DIR
export RUSTFLAGS="-C target-feature=-crt-static -C linker=$(ls ${toolchain}/bin/*-openwrt-linux-gcc)"
cargo build -r --target x86_64-unknown-linux-musl --features tls
```

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

