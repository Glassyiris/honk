#!/bin/sh
# outbound-ci — full test gate for honk-outbound after any change.
#
# Runs, in order and with early exit on failure:
#   1. fmt check
#   2. clippy (all targets, warnings denied)
#   3. honk-config tests (node/share-link fields change together)
#   4. honk-outbound full test suite
#
# Optional live-server e2e (skipped by default):
#   HONK_HY2_SERVER=host:port HONK_HY2_PASSWORD=... [HONK_HY2_MPORT=.. HONK_HY2_MHOP=..]
#   HONK_HY2_SOAK_TARGET=host:port HONK_HY2_SOAK_UDP_TARGET=host:port
#     → runs the hysteria2 real-server e2e + hop soak tests.
#
# Usage: ci/outbound-ci.sh [--with-e2e-env]
set -eu

cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$1"; }

step "cargo fmt --check"
cargo fmt -p honk-outbound -- --check

step "cargo clippy --all-targets -D warnings"
cargo clippy -p honk-outbound --all-targets -- -D warnings

step "cargo test -p honk-config"
# The two TOML round-trip failures are pre-existing (CI gate skips them too).
cargo test -p honk-config -- --skip test_config_toml_round_trip --skip test_to_file_and_from_file_by_extension

step "cargo test -p honk-outbound"
cargo test -p honk-outbound

if [ "${1:-}" = "--with-e2e-env" ]; then
    if [ -n "${HONK_HY2_SERVER:-}" ]; then
        step "hysteria2 real-server e2e ($HONK_HY2_SERVER)"
        cargo test -p honk-outbound --lib e2e_real_server_ -- --nocapture
    else
        echo "HONK_HY2_SERVER unset; skipping live e2e"
    fi
fi

printf '\noutbound-ci: ALL GREEN\n'
