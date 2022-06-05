### Build for openwrt


```bash
rustup target add -v x86_64-unknown-linux-musl
export PKG_CONFIG_SYSROOT_DIR=${openwrt}/staging_dir/target-x86_64_musl
export TARGET_CC=${openwrt}/staging_dir/toolchain-x86_64_gcc-8.4.0_musl/bin/x86_64-openwrt-linux-gcc
export STAGING_DIR=${openwrt}/staging_dir/target-x86_64_musl
export RUSTFLAGS='-C target-feature=-crt-static -C linker=${openwrt}/staging_dir/toolchain-x86_64_gcc-8.4.0_musl/bin/x86_64-openwrt-linux-gcc'
cargo build -r --target x86_64-unknown-linux-musl
```
