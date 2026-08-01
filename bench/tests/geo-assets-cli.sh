#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/honk-geo-test.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/source" "$TMP/etc/dae" "$TMP/attempt"
printf 'geosite-fixture\n' >"$TMP/source/dlc.dat"
printf 'geoip-fixture\n' >"$TMP/source/geoip.dat"
printf 'original-site\n' >"$TMP/etc/dae/geosite.dat"
chmod 0640 "$TMP/etc/dae/geosite.dat"
before=$(stat -c '%i|%u|%g|%a' "$TMP/etc/dae/geosite.dat")
before_sha=$(sha256sum "$TMP/etc/dae/geosite.dat" | awk '{print $1}')
HONK_DAE_DIR="$TMP/etc/dae" HONK_GEOSITE_URL="file://$TMP/source/dlc.dat" HONK_GEOIP_URL="file://$TMP/source/geoip.dat" bash "$ROOT/bench/prepare-test-assets.sh" --capture --attempt-dir "$TMP/attempt"
manifest="$TMP/attempt/assets/geo/geo-assets.json"
state="$TMP/install-state.json"
HONK_DAE_DIR="$TMP/etc/dae" bash "$ROOT/bench/prepare-test-assets.sh" --install-from-manifest "$manifest" --state "$state"
[[ $(cat "$TMP/etc/dae/geosite.dat") == geosite-fixture ]] || exit 1
HONK_DAE_DIR="$TMP/etc/dae" bash "$ROOT/bench/prepare-test-assets.sh" --restore --state "$state"
[[ $(stat -c '%i|%u|%g|%a' "$TMP/etc/dae/geosite.dat") == "$before" ]] || exit 1
[[ $(sha256sum "$TMP/etc/dae/geosite.dat" | awk '{print $1}') == "$before_sha" ]] || exit 1
[[ ! -e $TMP/etc/dae/geoip.dat ]] || exit 1
cp "$manifest" "$TMP/bad.json"
truncate -s 1 "$TMP/attempt/assets/geo/geoip.dat"
if HONK_DAE_DIR="$TMP/etc/dae" bash "$ROOT/bench/prepare-test-assets.sh" --install-from-manifest "$TMP/bad.json" --state "$TMP/bad-state.json" >"$TMP/bad.out" 2>"$TMP/bad.err"; then exit 1; fi
printf 'geo asset CLI tests passed\n'
