#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
IPROUTE=/run/current-system/sw/bin/ip
TC=/run/current-system/sw/bin/tc
NETNS=honkbench-client
HOST_VETH=honkbench-host
CLIENT_VETH=honkbench-peer
HOST_ADDRESS=198.18.0.1
CLIENT_ADDRESS=198.18.0.2
LOCK=${HONK_POLICY_LAB_LOCK:-/tmp/honk-policy-lab.lock}

usage() {
	cat <<'EOF'
Usage:
  sudo bash bench/honk-policy-lab.sh --suite self-test --output-dir DIR
  bash bench/honk-policy-lab.sh --suite generate --output-dir DIR

Suites:
  self-test  Run real local TCP, UDP, and DNS through both SOCKS5 relays.
  generate   Generate four isolated variant state trees without privileges.

DIR must be an absolute path. Self-test attempts the repository-owned netns
honkbench-client. If the execution sandbox denies netlink, it records a bounded
PRECONDITION artifact and still exercises the identical services on loopback.
EOF
}

die() { printf 'honk-policy-lab: %s\n' "$*" >&2; exit 2; }

suite=''
output_dir=''
while (($#)); do
	case $1 in
	--suite) (($# >= 2)) || die '--suite needs a value'; suite=$2; shift 2 ;;
	--output-dir) (($# >= 2)) || die '--output-dir needs a value'; output_dir=$2; shift 2 ;;
	--help|-h) usage; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done
[[ $suite == self-test || $suite == generate ]] || die '--suite must be self-test or generate'
[[ -n $output_dir ]] || die '--output-dir is required'
[[ $output_dir == /* ]] || die '--output-dir must be absolute'
mkdir -p -- "$output_dir"
python3 "$ROOT/bench/generate-honk-lab.py" --output-dir "$output_dir" --runs 1
[[ $suite == self-test ]] || exit 0
[[ $EUID == 0 ]] || die 'self-test requires root'
for tool in python3 timeout "$IPROUTE" "$TC" flock; do
	[[ -x $tool ]] || command -v "$tool" >/dev/null || die "missing prerequisite: $tool"
done

exec 9>"$LOCK"
flock -n 9 || die 'another honk policy lab owns the fixed topology'
pids=()
topology=loopback
bind_address=127.0.0.1
probe_prefix=()
baseline_netns=$({ $IPROUTE netns list 2>/dev/null || true; } | sha256sum | awk '{print $1}')
baseline_qdisc=$({ $TC qdisc show 2>/dev/null || true; } | sha256sum | awk '{print $1}')
baseline_fd=$(find /proc/$$/fd -maxdepth 1 -type l 2>/dev/null | wc -l)

cleanup() {
	local status=$? pid
	trap - EXIT INT TERM
	for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
	for pid in "${pids[@]}"; do
		if ! timeout 2s sh -c "while kill -0 '$pid' 2>/dev/null; do sleep 0.02; done"; then
			kill -KILL "$pid" 2>/dev/null || true
		fi
		wait "$pid" 2>/dev/null || true
	done
	if [[ $topology == netns ]]; then
		$TC qdisc del dev "$HOST_VETH" root 2>/dev/null || true
		$IPROUTE netns del "$NETNS" 2>/dev/null || true
		$IPROUTE link del "$HOST_VETH" 2>/dev/null || true
	fi
	local final_netns final_qdisc final_fd clean
	final_netns=$({ $IPROUTE netns list 2>/dev/null || true; } | sha256sum | awk '{print $1}')
	final_qdisc=$({ $TC qdisc show 2>/dev/null || true; } | sha256sum | awk '{print $1}')
	final_fd=$(find /proc/$$/fd -maxdepth 1 -type l 2>/dev/null | wc -l)
	clean=false
	[[ $baseline_netns == "$final_netns" && $baseline_qdisc == "$final_qdisc" && $final_fd -le $((baseline_fd + 1)) ]] && clean=true
	python3 - "$output_dir/cleanup-receipt.json" "$clean" "$topology" "$baseline_netns" "$final_netns" "$baseline_qdisc" "$final_qdisc" "$baseline_fd" "$final_fd" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = {"schema": 1, "clean": sys.argv[2] == "true", "topology": sys.argv[3], "netnsBeforeSha256": sys.argv[4], "netnsAfterSha256": sys.argv[5], "qdiscBeforeSha256": sys.argv[6], "qdiscAfterSha256": sys.argv[7], "fdBefore": int(sys.argv[8]), "fdAfter": int(sys.argv[9])}
path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
PY
	if [[ -f $output_dir/probe-a.json && -f $output_dir/probe-b.json ]]; then
		python3 "$ROOT/bench/verify-honk-lab.py" --output-dir "$output_dir" >/dev/null 2>&1 || status=1
	elif ((status != 77)); then
		status=1
	fi
	[[ $clean == true ]] || status=1
	exit "$status"
}
trap cleanup EXIT INT TERM

if $IPROUTE netns add "$NETNS" 2>"$output_dir/netns-preflight.stderr"; then
	topology=netns
	bind_address=$HOST_ADDRESS
	$IPROUTE link add "$HOST_VETH" type veth peer name "$CLIENT_VETH"
	$IPROUTE link set "$CLIENT_VETH" netns "$NETNS"
	$IPROUTE addr add "$HOST_ADDRESS/24" dev "$HOST_VETH"
	$IPROUTE link set "$HOST_VETH" up
	$IPROUTE netns exec "$NETNS" "$IPROUTE" addr add "$CLIENT_ADDRESS/24" dev "$CLIENT_VETH"
	$IPROUTE netns exec "$NETNS" "$IPROUTE" link set lo up
	$IPROUTE netns exec "$NETNS" "$IPROUTE" link set "$CLIENT_VETH" up
	$TC qdisc add dev "$HOST_VETH" root netem delay 1ms
	probe_prefix=($IPROUTE netns exec "$NETNS")
	printf '{"schema":1,"status":"PASS","topology":"netns"}\n' >"$output_dir/preconditions.json"
else
	printf '{"schema":1,"status":"PRECONDITION","reason":"netlink denied; exercised loopback services","topology":"loopback"}\n' >"$output_dir/preconditions.json"
fi

if ! python3 - <<'PY'
import socket
try:
    resource = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError:
    raise SystemExit(1) from None
else:
    resource.close()
PY
then
	printf '{"schema":1,"status":"PRECONDITION","reason":"AF_INET sockets denied by execution sandbox"}\n' >"$output_dir/traffic-precondition.json"
	exit 77
fi

python3 "$ROOT/bench/lab-targets.py" --bind "$bind_address" --ready "$output_dir/targets.ready" --trace "$output_dir/targets.jsonl" >"$output_dir/targets.stdout" 2>"$output_dir/targets.stderr" &
pids+=("$!")
python3 "$ROOT/bench/lab-socks5.py" --bind "$bind_address" --port 11080 --relay-id A --delay-ms 2 --ready "$output_dir/relay-a.ready" --trace "$output_dir/relay-a.jsonl" >"$output_dir/relay-a.stdout" 2>"$output_dir/relay-a.stderr" &
pids+=("$!")
python3 "$ROOT/bench/lab-socks5.py" --bind "$bind_address" --port 11081 --relay-id B --delay-ms 7 --ready "$output_dir/relay-b.ready" --trace "$output_dir/relay-b.jsonl" >"$output_dir/relay-b.stdout" 2>"$output_dir/relay-b.stderr" &
pids+=("$!")
if [[ ${HONK_LAB_STUBBORN_HELPER:-0} == 1 ]]; then
	sh -c 'trap "" TERM; while :; do sleep 1; done' &
	pids+=("$!")
fi
for ready in targets relay-a relay-b; do
	timeout 5s sh -c "until test -s '$output_dir/$ready.ready'; do sleep 0.02; done"
done
if [[ -n ${HONK_LAB_HOLD_AFTER_SETUP:-} ]]; then sleep "$HONK_LAB_HOLD_AFTER_SETUP"; fi
"${probe_prefix[@]}" python3 "$ROOT/bench/lab-probe.py" --relay "$bind_address:11080" --target "$bind_address" --output "$output_dir/probe-a.json"
"${probe_prefix[@]}" python3 "$ROOT/bench/lab-probe.py" --relay "$bind_address:11081" --target "$bind_address" --output "$output_dir/probe-b.json"
python3 "$ROOT/bench/verify-honk-lab.py" --output-dir "$output_dir"
