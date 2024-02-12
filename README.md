### Usage
```
iptv [Options]

Options:
  -u, --user <USER>                      Login username
  -p, --passwd <PASSWD>                  Login password
  -m, --mac <MAC>                        MAC address
  -i, --imei <IMEI>                      IMEI [default: ]
  -b, --bind <BIND>                      bind address:port [default: 127.0.0.1:7878]
  -a, --address <ADDRESS>                ip address/interface name [default: ]
  -I, --interface <INTERFACE>            interface to request
      --extra-playlist <EXTRA_PLAYLIST>  url to extra m3u
      --extra-xmltv <EXTRA_XMLTV>        url to extra xmltv
      --udp-proxy <UDP_PROXY>            udp proxy address:port
  -h, --help                             Print help
  -V, --version                          Print version
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
UDP_PROXY=192.168.1.1:4022
INTERFACE=pppoe-iptv
BIND=0.0.0.0:7878

start() {
        ( RUST_LOG=info /usr/bin/iptv -u $USER -p $PASSWD -m $MAC -b $BIND --udp-proxy $UDP_PROXY -I $INTERFACE 2>&1 & echo $! >&3 ) 3>/var/run/iptv.pid | logger -t "iptv-proxy" &
}

stop() {
        if [ -f /var/run/iptv.pid ]; then
                kill -9 $(cat /var/run/iptv.pid) 2>/dev/null
                rm -f /var/run/iptv.pid
        fi
}
```

### Build for openwrt
```bash
rustup target add -v x86_64-unknown-linux-musl
export PKG_CONFIG_SYSROOT_DIR=${openwrt}/staging_dir/target-x86_64_musl
toolchain="$(ls -d ${openwrt}/staging_dir/toolchain-x86_64_gcc-*_musl)"
export TARGET_CC=${toolchain}/bin/x86_64-openwrt-linux-gcc
export STAGING_DIR=${openwrt}/staging_dir/target-x86_64_musl
export RUSTFLAGS="-C target-feature=-crt-static -C linker=${toolchain}/bin/x86_64-openwrt-linux-gcc"
cargo build -r --target x86_64-unknown-linux-musl
```
