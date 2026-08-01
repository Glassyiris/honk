#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

output=''
while (($#)); do
	case $1 in
	--output) output=$2; shift 2 ;;
	*) printf 'check-honk-lab-prereqs: unknown argument: %s\n' "$1" >&2; exit 2 ;;
	esac
done
[[ -n $output ]] || { printf 'check-honk-lab-prereqs: --output is required\n' >&2; exit 2; }

nightly=false
bpf_linker=false
wrapper=false
readelf=false
root=false
cap_bpf=false
rustup run nightly rustc --version >/dev/null 2>&1 && nightly=true
command -v bpf-linker >/dev/null 2>&1 && bpf_linker=true
[[ -x /root/.cargo/bin/bpf-linker-wrapper ]] && wrapper=true
command -v readelf >/dev/null 2>&1 && readelf=true
[[ $EUID == 0 ]] && root=true
if command -v capsh >/dev/null 2>&1 && capsh --print 2>/dev/null | grep -Eq 'Bounding set =.*cap_bpf'; then cap_bpf=true; fi
status=PASS
[[ $nightly == true && $bpf_linker == true && $wrapper == true && $readelf == true && $root == true && $cap_bpf == true ]] || status=PRECONDITION
python3 - "$output" "$status" "$nightly" "$bpf_linker" "$wrapper" "$readelf" "$root" "$cap_bpf" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
keys = ("nightly", "bpfLinker", "wrapper", "readelf", "root", "capBpfBounding")
value = {"schema": 1, "status": sys.argv[2], "checks": dict(zip(keys, (item == "true" for item in sys.argv[3:]), strict=True))}
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
PY
[[ $status == PASS ]] || exit 77
