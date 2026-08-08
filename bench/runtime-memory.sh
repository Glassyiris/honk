#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly HELPER="$SCRIPT_DIR/runtime-memory-workload.py"
readonly LOCK_FILE=${HONK_RUNTIME_MEMORY_LOCK_FILE:-/run/lock/honk-runtime-memory.lock}

baseline_bin=''
candidate_bin=''
baseline_commit=''
candidate_commit=''
config_path=''
target=''
runs=5
output=''
fixture=''
netns=lab
controller=http://127.0.0.1:9090
worker_threads=16
baseline_collect_secs=60
candidate_collect_secs=60
work_dir=''
run_artifacts=''
output_staging=''
active_pid=''
active_pgid=''
active_starttime=''
active_executable=''
active_log=''
benchmark_config=''
baseline_binary_pin=''
candidate_binary_pin=''

usage() {
	cat <<'EOF'
Usage:
  sudo bench/runtime-memory.sh \
    --baseline-bin PATH --baseline-commit COMMIT \
    --candidate-bin PATH --candidate-commit COMMIT \
    --config PATH --target IP --runs N --output FILE
  bench/runtime-memory.sh --fixture FILE --runs N --output FILE

Live mode runs alternating baseline/candidate arms in netns "lab" by default.
The externally generated standalone, subscription-free config is snapshotted once beside its
source so relative resolution keeps its original boundary; that same private
snapshot is used by every arm and removed after the run. Each arm covers cold
settling, live reload continuity, AnyTLS open/bandwidth, 64-way churn,
8-slow/1000-fast backpressure, and a 130-second settled curve. Output is
atomically published only after every arm validates; diagnostics and engine
logs remain separate.

Options:
  --baseline-bin PATH
  --baseline-commit COMMIT           lowercase 40- or 64-hex Git object ID
  --candidate-bin PATH
  --candidate-commit COMMIT          lowercase 40- or 64-hex Git object ID
  --config PATH
  --target IP
  --runs N                         default: 5
  --output FILE
  --netns NAME                     default: lab
  --controller URL                 default: http://127.0.0.1:9090
  --worker-threads N               default: 16
  --baseline-collect-secs N        default: 60
  --candidate-collect-secs N       default: 60
  --fixture FILE                   deterministic, unprivileged contract mode
  -h, --help
EOF
}

die() {
	printf 'runtime-memory: %s\n' "$*" >&2
	exit 1
}

require_positive_integer() {
	local name=$1 value=$2
	[[ $value =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer"
}

require_nonnegative_integer() {
	local name=$1 value=$2
	[[ $value =~ ^[0-9]+$ ]] || die "$name must be a non-negative integer"
}

require_u64() {
	local name=$1 value=$2 normalized
	require_nonnegative_integer "$name" "$value"
	normalized=$value
	while ((${#normalized} > 1)) && [[ ${normalized:0:1} == 0 ]]; do
		normalized=${normalized:1}
	done
	if ((${#normalized} > 20)) || { ((${#normalized} == 20)) && [[ $normalized > 18446744073709551615 ]]; }; then
		die "$name must fit in an unsigned 64-bit integer"
	fi
}

require_regular_file() {
	local name=$1 path=$2
	[[ -f $path && ! -L $path ]] || die "$name must be a regular non-symlink file: $path"
}

require_standalone_config() {
	python3 - "$1" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
index = 0
depth = 0
dae_section_found = False
while index < len(text):
    char = text[index]
    if char == "#":
        newline = text.find("\n", index)
        index = len(text) if newline < 0 else newline + 1
        continue
    if char in "'\"":
        quote = char
        index += 1
        while index < len(text):
            if text[index] == "\\":
                index += 2
            elif text[index] == quote:
                index += 1
                break
            else:
                index += 1
        continue
    if char == "{":
        depth += 1
        index += 1
        continue
    if char == "}":
        depth = max(0, depth - 1)
        index += 1
        continue
    if depth == 0 and (char.isalpha() or char == "_"):
        start = index
        index += 1
        while index < len(text) and (text[index].isalnum() or text[index] in "_-"):
            index += 1
        section = text[start:index]
        cursor = index
        while cursor < len(text):
            if text[cursor].isspace():
                cursor += 1
            elif text[cursor] == "#":
                newline = text.find("\n", cursor)
                cursor = len(text) if newline < 0 else newline + 1
            else:
                break
        if cursor < len(text) and text[cursor] == "{":
            if section in {"include", "subscription"}:
                raise SystemExit(
                    "runtime-memory: live benchmark config must not use include or subscription"
                )
            if section in {"global", "node", "group", "routing", "dns", "experimental"}:
                dae_section_found = True
    else:
        index += 1
if not dae_section_found:
    raise SystemExit("runtime-memory: live benchmark config must use dae syntax")
PY
}

require_executable_file() {
	local name=$1 path=$2
	[[ -f $path && ! -L $path && -x $path ]] ||
		die "$name must be an executable regular non-symlink file: $path"
}

require_commit() {
	local name=$1 value=$2
	[[ $value =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] ||
		die "$name must be a lowercase 40- or 64-hex Git object ID"
}

read_starttime() {
	python3 - "$1" <<'PY'
from pathlib import Path
import sys
raw = Path(f"/proc/{sys.argv[1]}/stat").read_text()
print(raw[raw.rfind(")") + 2:].split()[19])
PY
}

executable_identity() {
	stat -Lc '%d:%i' -- "$1"
}

binary_pin() {
	python3 - "$1" <<'PY'
from pathlib import Path
import hashlib
import sys

path = Path(sys.argv[1]).resolve(strict=True)
info = path.stat()
with path.open("rb") as source:
    digest = hashlib.file_digest(source, "sha256").hexdigest()
print(f"{info.st_dev}:{info.st_ino}:{info.st_size}:{digest}")
PY
}

require_binary_pin() {
	local stage=$1 path=$2 expected=$3 observed
	observed=$(binary_pin "$path") || return 1
	[[ $observed == "$expected" ]] || {
		printf 'runtime-memory: selected binary changed during %s\n' "$stage" >&2
		return 1
	}
}

require_active_identity() {
	local stage=$1 observed_start observed_executable
	[[ -n $active_pid && -r /proc/$active_pid/stat ]] || {
		printf 'runtime-memory: measured process disappeared during %s\n' "$stage" >&2
		return 1
	}
	observed_start=$(read_starttime "$active_pid") || return 1
	[[ $observed_start == "$active_starttime" ]] || {
		printf 'runtime-memory: PID identity changed during %s\n' "$stage" >&2
		return 1
	}
	observed_executable=$(executable_identity "/proc/$active_pid/exe") || return 1
	[[ $observed_executable == "$active_executable" ]] || {
		printf 'runtime-memory: executable identity changed during %s\n' "$stage" >&2
		return 1
	}
}

stop_active() {
	local rc=0 attempt
	if [[ -n $active_pid ]]; then
		if [[ -r /proc/$active_pid/stat ]] && [[ $(read_starttime "$active_pid" 2>/dev/null || true) == "$active_starttime" ]]; then
			kill -TERM -- "-$active_pgid" 2>/dev/null || true
			for ((attempt = 0; attempt < 960; attempt++)); do
				[[ -r /proc/$active_pid/stat ]] || break
				[[ $(read_starttime "$active_pid" 2>/dev/null || true) == "$active_starttime" ]] || break
				sleep 0.25
			done
			if [[ -r /proc/$active_pid/stat ]] && [[ $(read_starttime "$active_pid" 2>/dev/null || true) == "$active_starttime" ]]; then
				printf 'runtime-memory: engine did not stop within 240 seconds\n' >&2
				kill -KILL -- "-$active_pgid" 2>/dev/null || true
				rc=1
			fi
		fi
		wait "$active_pid" 2>/dev/null || true
	fi
	active_pid=''
	active_pgid=''
	active_starttime=''
	active_executable=''
	active_log=''
	return "$rc"
}

cleanup() {
	local rc=$?
	set +e
	stop_active
	[[ -z $work_dir ]] || rm -rf -- "$work_dir"
	[[ -z $output_staging ]] || rm -f -- "$output_staging"
	[[ -z $benchmark_config ]] || rm -f -- "$benchmark_config"
	exit "$rc"
}

controller_socket_owned_by_active_pid() {
	python3 - "$active_pid" "$controller" <<'PY'
from pathlib import Path
import ipaddress
import re
import socket
import sys
from urllib.parse import urlsplit

pid, raw_url = sys.argv[1:]
parsed = urlsplit(raw_url)
if parsed.scheme != "http" or parsed.hostname is None:
    raise SystemExit(1)
port = parsed.port or 80

def normalized(address):
    value = ipaddress.ip_address(address.split("%", 1)[0])
    return getattr(value, "ipv4_mapped", None) or value

wanted = {
    normalized(sockaddr[0])
    for _, _, _, _, sockaddr in socket.getaddrinfo(
        parsed.hostname, port, type=socket.SOCK_STREAM
    )
}
inodes = set()
for descriptor in Path(f"/proc/{pid}/fd").iterdir():
    try:
        target = descriptor.readlink()
    except FileNotFoundError:
        continue
    matched = re.fullmatch(r"socket:\[(\d+)\]", str(target))
    if matched:
        inodes.add(matched.group(1))

def proc_address(table_name, encoded):
    raw = bytes.fromhex(encoded)
    if table_name == "tcp":
        packed = raw[::-1]
        family = socket.AF_INET
    else:
        packed = b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
        family = socket.AF_INET6
    return normalized(socket.inet_ntop(family, packed))

for table_name in ("tcp", "tcp6"):
    table = Path(f"/proc/{pid}/net/{table_name}")
    if not table.exists():
        continue
    for line in table.read_text(encoding="ascii").splitlines()[1:]:
        fields = line.split()
        if len(fields) <= 9 or fields[3] != "0A" or fields[9] not in inodes:
            continue
        encoded_address, encoded_port = fields[1].rsplit(":", 1)
        local_address = proc_address(table_name, encoded_address)
        if int(encoded_port, 16) == port and (
            local_address.is_unspecified or local_address in wanted
        ):
            raise SystemExit(0)
raise SystemExit(1)
PY
}

wait_ready() {
	local deadline=$((SECONDS + 30))
	while ((SECONDS < deadline)); do
		require_active_identity startup || return 1
		if curl --fail --silent --max-time 1 "$controller/version" >/dev/null 2>&1 &&
			controller_socket_owned_by_active_pid; then
			require_active_identity ready
			return
		fi
		sleep 0.25
	done
	printf 'runtime-memory: engine did not expose the Clash API\n' >&2
	return 1
}

start_engine() {
	local arm=$1 selected=$2 collect_secs=$3 run=$4 expected_pin=$5
	local pid_file launcher expected_device expected_inode expected_size expected_hash expected_identity
	require_binary_pin "$arm pre-start" "$selected" "$expected_pin" ||
		die "selected $arm binary changed before start"
	IFS=: read -r expected_device expected_inode expected_size expected_hash <<<"$expected_pin"
	expected_identity="$expected_device:$expected_inode"
	if curl --fail --silent --max-time 1 "$controller/version" >/dev/null 2>&1; then
		die 'residual Clash API listener before engine start'
	fi
	[[ -n $benchmark_config ]] || die 'benchmark config snapshot is unavailable'
	active_log="$run_artifacts/run-${run}-${arm}.engine.log"
	pid_file="$work_dir/run-${run}-${arm}.pid"
	setsid bash -c 'pid_file=$1; shift; printf "%s\n" "$$" >"$pid_file"; exec "$@"' \
		bash "$pid_file" env -u MIMALLOC_ALLOW_THP RUST_LOG=info \
		TOKIO_WORKER_THREADS="$worker_threads" HONK_MI_COLLECT_SECS="$collect_secs" \
		"$selected" --config "$benchmark_config" >"$active_log" 2>&1 &
	launcher=$!
	for _ in {1..40}; do
		[[ -s $pid_file ]] && break
		kill -0 "$launcher" 2>/dev/null || die "engine launcher exited; see $active_log"
		sleep 0.05
	done
	[[ -s $pid_file ]] || die 'engine launcher did not publish its PID'
	active_pid=$(<"$pid_file")
	active_pgid=$active_pid
	active_starttime=$(read_starttime "$active_pid") || die "engine exited; see $active_log"
	active_executable=$(executable_identity "/proc/$active_pid/exe") || die 'cannot read engine executable'
	[[ $active_executable == "$expected_identity" ]] || die 'launcher did not exec the selected binary'
	wait_ready || die "engine readiness failed; see $active_log"
}

append_validated_output() {
	local source=$1
	[[ -s $source ]] || die 'workload emitted no JSONL rows'
	python3 - "$source" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    rows = [json.loads(line) for line in source if line.strip()]
if not rows:
    raise SystemExit("runtime-memory: workload emitted no rows")
if any(not isinstance(row, dict) for row in rows):
    raise SystemExit("runtime-memory: workload row is not an object")
PY
	cat -- "$source" >>"$output_staging"
}

run_fixture_arm() {
	local arm=$1 run=$2 temporary="$work_dir/fixture-${run}-${arm}.jsonl"
	python3 "$HELPER" fixture --fixture "$fixture" --arm "$arm" --run "$run" >"$temporary"
	append_validated_output "$temporary"
}

run_live_arm() {
	local arm=$1 run=$2 selected source_commit collect_secs expected_pin temporary
	local expected_device expected_inode expected_size expected_hash
	case $arm in
	baseline)
		selected=$baseline_bin
		collect_secs=$baseline_collect_secs
		source_commit=$baseline_commit
		expected_pin=$baseline_binary_pin
		;;
	candidate)
		selected=$candidate_bin
		collect_secs=$candidate_collect_secs
		source_commit=$candidate_commit
		expected_pin=$candidate_binary_pin
		;;
	esac
	IFS=: read -r expected_device expected_inode expected_size expected_hash <<<"$expected_pin"
	start_engine "$arm" "$selected" "$collect_secs" "$run" "$expected_pin"
	temporary="$work_dir/run-${run}-${arm}.jsonl"
	if ! python3 "$HELPER" run \
		--pid "$active_pid" --binary "$selected" --source-commit "$source_commit" \
		--expected-binary-device "$expected_device" --expected-binary-inode "$expected_inode" \
		--expected-binary-size "$expected_size" --expected-binary-sha256 "$expected_hash" \
		--config "$benchmark_config" --engine-log "$active_log" --arm "$arm" --run "$run" \
		--run-dir "$work_dir" --target "$target" --netns "$netns" --controller "$controller" \
		--worker-threads "$worker_threads" --collect-secs "$collect_secs" >"$temporary"; then
		printf 'runtime-memory: workload failed; see %s\n' "$active_log" >&2
		return 1
	fi
	require_active_identity workload || return 1
	require_binary_pin "$arm post-workload" "$selected" "$expected_pin" || return 1
	stop_active || return 1
	append_validated_output "$temporary"
}

while (($#)); do
	case $1 in
	--baseline-bin) (($# >= 2)) || die '--baseline-bin requires a value'; baseline_bin=$2; shift 2 ;;
	--baseline-commit) (($# >= 2)) || die '--baseline-commit requires a value'; baseline_commit=$2; shift 2 ;;
	--candidate-bin) (($# >= 2)) || die '--candidate-bin requires a value'; candidate_bin=$2; shift 2 ;;
	--candidate-commit) (($# >= 2)) || die '--candidate-commit requires a value'; candidate_commit=$2; shift 2 ;;
	--config) (($# >= 2)) || die '--config requires a value'; config_path=$2; shift 2 ;;
	--target) (($# >= 2)) || die '--target requires a value'; target=$2; shift 2 ;;
	--runs) (($# >= 2)) || die '--runs requires a value'; runs=$2; shift 2 ;;
	--output) (($# >= 2)) || die '--output requires a value'; output=$2; shift 2 ;;
	--netns) (($# >= 2)) || die '--netns requires a value'; netns=$2; shift 2 ;;
	--controller) (($# >= 2)) || die '--controller requires a value'; controller=$2; shift 2 ;;
	--worker-threads) (($# >= 2)) || die '--worker-threads requires a value'; worker_threads=$2; shift 2 ;;
	--baseline-collect-secs) (($# >= 2)) || die '--baseline-collect-secs requires a value'; baseline_collect_secs=$2; shift 2 ;;
	--candidate-collect-secs) (($# >= 2)) || die '--candidate-collect-secs requires a value'; candidate_collect_secs=$2; shift 2 ;;
	--fixture) (($# >= 2)) || die '--fixture requires a value'; fixture=$2; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done

require_executable_file helper "$HELPER"
require_positive_integer runs "$runs"
require_positive_integer worker-threads "$worker_threads"
require_u64 baseline-collect-secs "$baseline_collect_secs"
require_u64 candidate-collect-secs "$candidate_collect_secs"
[[ -n $output ]] || die '--output is required'
[[ ! -e $output ]] || die "output already exists: $output"
mkdir -p -- "$(dirname -- "$output")"
run_artifacts="${output}.runs"
[[ ! -e $run_artifacts ]] || die "run artifact directory already exists: $run_artifacts"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/honk-runtime-memory.XXXXXX")
trap cleanup EXIT INT TERM HUP
output_staging=$(mktemp "${output}.tmp.XXXXXX")
mkdir -p -- "$run_artifacts"
mkdir -p -- "$(dirname -- "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -n 9 || die "another runtime-memory benchmark holds $LOCK_FILE"

if [[ -n $fixture ]]; then
	require_regular_file fixture "$fixture"
else
	((EUID == 0)) || die 'live mode must run as root'
	require_executable_file baseline-bin "$baseline_bin"
	require_executable_file candidate-bin "$candidate_bin"
	require_commit baseline-commit "$baseline_commit"
	require_regular_file config "$config_path"
	require_commit candidate-commit "$candidate_commit"
	baseline_binary_pin=$(binary_pin "$baseline_bin") || die 'cannot pin baseline binary'
	candidate_binary_pin=$(binary_pin "$candidate_bin") || die 'cannot pin candidate binary'
	config_dir=$(dirname -- "$config_path")
	benchmark_config=$(mktemp "$config_dir/.honk-runtime-memory.XXXXXX.snapshot") ||
		die 'cannot create adjacent config snapshot'
	cp -- "$config_path" "$benchmark_config"
	chmod 0400 -- "$benchmark_config"
	require_standalone_config "$benchmark_config"
	[[ -n $target ]] || die '--target is required in live mode'
	python3 - "$target" <<'PY'
import ipaddress
import sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError as error:
    raise SystemExit("runtime-memory: target must be an IP address") from error
PY
	command -v ip >/dev/null || die 'ip is required for the lab netns'
	command -v iperf3 >/dev/null || die 'iperf3 is required for throughput measurements'
	command -v curl >/dev/null || die 'curl is required for readiness checks'
fi

for ((run = 1; run <= runs; run++)); do
	if ((run % 2 == 1)); then
		arms=(baseline candidate)
	else
		arms=(candidate baseline)
	fi
	for arm in "${arms[@]}"; do
		printf 'runtime-memory: run=%s arm=%s\n' "$run" "$arm" >&2
		if [[ -n $fixture ]]; then
			run_fixture_arm "$arm" "$run"
		else
			run_live_arm "$arm" "$run"
		fi
	done
done

[[ -s $output_staging ]] || die 'benchmark produced no validated output'
ln -- "$output_staging" "$output" || die "cannot atomically publish output: $output"
rm -f -- "$output_staging"
output_staging=''

printf 'runtime-memory: results=%s artifacts=%s\n' "$output" "$run_artifacts" >&2
