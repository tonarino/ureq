#!/bin/bash
set -eu

export RUST_BACKTRACE=1
export RUSTFLAGS="-D dead_code -D unused-variables -D unused"

for feature in "" tls json charset cookies socks-proxy "tls native-certs" native-tls gzip brotli http-interop http-crate digest-auth; do
  if ! cargo test --no-default-features --features "testdeps ${feature}" ; then
    echo Command failed: cargo test --no-default-features --features \"testdeps ${feature}\"
    exit 1
  fi
done
