#!/bin/bash
# Builds the honk-netstack criterion bench and the tcp_bulk example for aarch64-linux-android, and
# tcp_bulk natively for a sanity run. Outputs land in $OUT (default android/scripts/out/): tcp_bulk,
# tcp_bulk-native, netstack-criterion and honk-commit (the revision they were built from).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${OUT:-$here/out}"
. "$here/android-env.sh"

mkdir -p "$out"
cd "$repo"
target=aarch64-linux-android
cargo build --release -p honk-netstack --example tcp_bulk --target "$target"
cargo build --release -p honk-netstack --example tcp_bulk
bench_json="$(cargo bench -p honk-netstack --bench stack --no-run --target "$target" \
    --message-format=json 2>/dev/null)"
bench_exe="$(printf '%s\n' "$bench_json" \
    | grep '"executable":"[^"]*/stack-[0-9a-f]*"' \
    | sed 's/.*"executable":"\([^"]*\)".*/\1/' | tail -1)"
[ -n "$bench_exe" ] || { echo "criterion bench executable not found" >&2; exit 1; }

cp "$repo/target/$target/release/examples/tcp_bulk" "$out/tcp_bulk"
cp "$repo/target/release/examples/tcp_bulk" "$out/tcp_bulk-native"
cp "$bench_exe" "$out/netstack-criterion"
git -C "$repo" rev-parse HEAD > "$out/honk-commit"
file "$out/tcp_bulk" "$out/netstack-criterion"
echo "honk $(cat "$out/honk-commit")"
