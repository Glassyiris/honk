#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

GEOSITE_URL=${HONK_GEOSITE_URL:-https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat}
GEOIP_URL=${HONK_GEOIP_URL:-https://github.com/v2fly/geoip/releases/latest/download/geoip.dat}
DAE_DIR=${HONK_DAE_DIR:-/etc/dae}

die() { printf 'prepare-test-assets: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum -- "$1" | awk '{print $1}'; }

mode=''
attempt_dir=''
manifest=''
state=''
while (($#)); do
	case $1 in
	--capture) mode=capture; shift ;;
	--install-from-manifest) (($# >= 2)) || die 'manifest argument missing'; mode=install; manifest=$2; shift 2 ;;
	--restore) mode=restore; shift ;;
	--attempt-dir) (($# >= 2)) || die 'attempt directory missing'; attempt_dir=$2; shift 2 ;;
	--state) (($# >= 2)) || die 'state path missing'; state=$2; shift 2 ;;
	--help|-h) printf 'Usage: prepare-test-assets.sh --capture --attempt-dir DIR | --install-from-manifest FILE --state FILE | --restore --state FILE\n'; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done

if [[ $mode == capture ]]; then
	[[ -n $attempt_dir ]] || die '--attempt-dir is required for capture'
	asset_dir=$attempt_dir/assets/geo
	mkdir -p "$asset_dir/restore"
	declare -a records=()
	for spec in "geosite.dat|$GEOSITE_URL|dlc.dat" "geoip.dat|$GEOIP_URL|geoip.dat"; do
		IFS='|' read -r name url download_name <<<"$spec"
		effective_file=$asset_dir/.${name}.url
		if ! timeout 60s curl --fail --location --silent --show-error --output "$asset_dir/$name" --write-out '%{url_effective}' "$url" >"$effective_file"; then
			printf '{"schema":1,"status":"PRECONDITION","reason":"geo download unavailable","asset":"%s"}\n' "$name" >"$asset_dir/capture-precondition.json"
			exit 77
		fi
		[[ -s $asset_dir/$name && ! -L $asset_dir/$name ]] || die "captured asset invalid: $name"
		records+=("$name|$(cat "$effective_file")|$(stat -c %s "$asset_dir/$name")|$(sha "$asset_dir/$name")|$download_name")
		rm -f "$effective_file"
	done
	for name in geosite.dat geoip.dat; do
		if [[ -e $DAE_DIR/$name ]]; then
			[[ -f $DAE_DIR/$name && ! -L $DAE_DIR/$name ]] || die "existing Geo path is not regular: $DAE_DIR/$name"
			cp -p -- "$DAE_DIR/$name" "$asset_dir/restore/$name"
			stat -c '%i|%u|%g|%a' "$DAE_DIR/$name" >"$asset_dir/restore/$name.meta"
		else
			printf 'absent\n' >"$asset_dir/restore/$name.meta"
		fi
	done
	python3 - "$asset_dir/geo-assets.json" "$DAE_DIR" "${records[@]}" <<'PY'
import json, pathlib, sys
path, dae_dir, *raw = sys.argv[1:]
assets = []
for item in raw:
    name, url, size, digest, source_name = item.split("|", 4)
    assets.append({"name": name, "sourceName": source_name, "resolvedUrl": url, "size": int(size), "sha256": digest})
pathlib.Path(path).write_text(json.dumps({"schema": 1, "daeDir": dae_dir, "assets": assets}, sort_keys=True, separators=(",", ":")) + "\n")
PY
	exit 0
fi

[[ -n $state ]] || die '--state is required'
if [[ $mode == install ]]; then
	[[ -f $manifest && ! -L $manifest ]] || die 'manifest must be a regular file'
	mkdir -p "$DAE_DIR"
	asset_dir=$(cd -- "$(dirname -- "$manifest")" && pwd)
	transaction="$DAE_DIR/.honk-geo-restore-$$"
	mkdir -m 700 "$transaction"
	python3 - "$manifest" "$asset_dir" <<'PY'
import hashlib, json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = pathlib.Path(sys.argv[2])
for asset in manifest["assets"]:
    path = root / asset["name"]
    data = path.read_bytes()
    if len(data) != asset["size"] or hashlib.sha256(data).hexdigest() != asset["sha256"]:
        raise SystemExit(f"asset hash mismatch: {path}")
PY
	declare -a state_rows=()
	for name in geosite.dat geoip.dat; do
		existed=false
		inode=0 owner=0 group=0 permissions=0 original_sha=''
		if [[ -e $DAE_DIR/$name ]]; then
			[[ -f $DAE_DIR/$name && ! -L $DAE_DIR/$name ]] || die "destination is not regular: $DAE_DIR/$name"
			existed=true
			IFS='|' read -r inode owner group permissions <<<"$(stat -c '%i|%u|%g|%a' "$DAE_DIR/$name")"
			original_sha=$(sha "$DAE_DIR/$name")
			mv -- "$DAE_DIR/$name" "$transaction/$name"
		fi
		install -m 0644 -- "$asset_dir/$name" "$DAE_DIR/.${name}.new"
		mv -- "$DAE_DIR/.${name}.new" "$DAE_DIR/$name"
		state_rows+=("$name|$existed|$inode|$owner|$group|$permissions|$original_sha")
	done
	python3 - "$state" "$DAE_DIR" "$transaction" "$manifest" "${state_rows[@]}" <<'PY'
import json, pathlib, sys
path, dae_dir, transaction, manifest, *raw = sys.argv[1:]
files = []
for item in raw:
    name, existed, inode, owner, group, mode, digest = item.split("|", 6)
    files.append({"name": name, "existed": existed == "true", "inode": int(inode), "owner": int(owner), "group": int(group), "mode": int(mode), "sha256": digest})
pathlib.Path(path).write_text(json.dumps({"schema": 1, "daeDir": dae_dir, "transactionDir": transaction, "manifest": str(pathlib.Path(manifest).resolve()), "files": files}, sort_keys=True, separators=(",", ":")) + "\n")
PY
	exit 0
fi

[[ $mode == restore ]] || die 'select --capture, --install-from-manifest, or --restore'
python3 - "$state" <<'PY'
import json, os, pathlib, shutil, sys
state_path = pathlib.Path(sys.argv[1])
state = json.loads(state_path.read_text())
root = pathlib.Path(state["daeDir"])
transaction = pathlib.Path(state["transactionDir"])
for item in state["files"]:
    destination = root / item["name"]
    if destination.exists():
        destination.unlink()
    if item["existed"]:
        os.replace(transaction / item["name"], destination)
shutil.rmtree(transaction)
PY
