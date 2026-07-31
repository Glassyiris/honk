#!/usr/bin/env bash
# UDP deployment benchmark driver. Fixture mode is deterministic and needs no
# privileges or network; live mode fails closed unless every hook is supplied.
set -Eeuo pipefail
umask 077

readonly CASES=(
	cold_endpoint
	steady_hit
	warm_session_cold_endpoint
	dns_hit
	dns_miss
	healthy_candidate
	blackholed_candidate
)
readonly LOCK_FILE="${HONK_UDP_LOCK_FILE:-/run/lock/honk-udp-latency.lock}"

usage() {
	cat <<'EOF'
Usage:
  udp-latency.sh --fixture DIR --samples N --runs N --offered-rate N
  sudo udp-latency.sh \
    --baseline-bin PATH --candidate-bin PATH --config PATH \
    --echo-target HOST:PORT --dns-target HOST:PORT \
    --samples N --runs N --offered-rate N

Live settings default from root's environment and may be overridden by CLI:
  HONK_UDP_TIMEOUT_SEC (default: 30)
  HONK_UDP_{START,READY,SETUP,PROBE,STATS,TEARDOWN,TOPOLOGY}_HOOK
  --timeout SECONDS and --{start,ready,setup,probe,stats,teardown,topology}-hook PATH

When using sudo, configure the root environment or use sudo --preserve-env for
these HONK_UDP_* variables. The driver supplies no built-in topology or hooks.
Fixture mode reads meta.json, samples.json, and stats.json from DIR and emits
only deterministic JSONL. Live hooks must be executable files (not snippets).
Every hook is invoked through env with variant, case, run, workdir, pid, pgid,
selected_bin, baseline_bin, candidate_bin, config, echo_target, dns_target,
samples, offered_rate, and timeout; start/topology have empty process fields.
Start must finish synchronous setup and then exec selected_bin; the driver checks
that executable identity after ready, setup, probe, and stats. A row is emitted
only after teardown and bounded verification that the owned process group is gone.
Existing positional hook arguments remain for compatibility. Probe must emit one
JSON object with latency_us, sent, received, cpu_pct, rss_kib, and fd_count.
Stats must emit queue_drops and warm_hit objects. Diagnostics go to stderr.
EOF
}

die() {
	printf 'udp-latency: %s\n' "$*" >&2
	exit 1
}

require_positive_integer() {
	local name=$1 value=$2
	[[ $value =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer"
}

require_executable_file() {
	local name=$1 path=$2
	[[ -f $path && -x $path ]] || die "$name must be an executable regular file: $path"
}

validate_target() {
	local name=$1 target=$2
	python3 - "$name" "$target" <<'PY'
import ipaddress
import re
import sys

name, raw = sys.argv[1:]
try:
    bracketed = raw.startswith("[")
    if bracketed:
        host, separator, port = raw[1:].partition("]:")
        if not separator:
            raise ValueError("IPv6 targets require [address]:port")
        if ipaddress.ip_address(host).version != 6:
            raise ValueError("bracketed targets require an IPv6 address")
    else:
        host, separator, port = raw.rpartition(":")
        if not separator or not host or ":" in host:
            raise ValueError("targets require IPv4:port, hostname:port, or [IPv6]:port")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            hostname = host[:-1] if host.endswith(".") else host
            labels = hostname.split(".")
            if not hostname or len(hostname) > 253 or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in labels
            ):
                raise ValueError("host is not a legal hostname")
    port_number = int(port)
    if not 1 <= port_number <= 65535:
        raise ValueError("port must be in 1..65535")
except ValueError as error:
    print(f"udp-latency: {name} is invalid ({error})", file=sys.stderr)
    raise SystemExit(1)
PY
}

hook_variant=''
hook_case=''
hook_run=''
hook_workdir=''
hook_pid=''
hook_pgid=''
hook_selected_bin=''
declare -a hook_environment=()

set_hook_context() {
	hook_variant=$1
	hook_case=$2
	hook_run=$3
	hook_workdir=$4
	hook_pid=$5
	hook_pgid=$6
	hook_selected_bin=''
	case $hook_variant in
	baseline) hook_selected_bin=$baseline_bin ;;
	candidate) hook_selected_bin=$candidate_bin ;;
	esac
}

build_hook_environment() {
	hook_environment=(
		"variant=$hook_variant"
		"case=$hook_case"
		"run=$hook_run"
		"workdir=$hook_workdir"
		"pid=$hook_pid"
		"pgid=$hook_pgid"
		"selected_bin=$hook_selected_bin"
		"baseline_bin=$baseline_bin"
		"candidate_bin=$candidate_bin"
		"config=$config_path"
		"echo_target=$echo_target"
		"dns_target=$dns_target"
		"samples=$samples"
		"offered_rate=$offered_rate"
		"timeout=$timeout_seconds"
	)
}

run_hook() {
	local label=$1 hook=$2 output=$3
	shift 3
	local error_file="${output}.stderr"
	build_hook_environment
	if timeout -k 5 "${timeout_seconds}s" env "${hook_environment[@]}" "$hook" "$@" 9>&- >"$output" 2>"$error_file"; then
		cat "$error_file" >&2
		return 0
	else
		local rc=$?
		if ((rc == 124)); then
			printf 'udp-latency: %s hook timed out after %ss\n' "$label" "$timeout_seconds" >&2
		else
			printf 'udp-latency: %s hook failed (exit %s)\n' "$label" "$rc" >&2
		fi
		cat "$error_file" >&2
		return "$rc"
	fi
}

active_launcher_pid=''
active_pid=''
active_pgid=''
active_starttime=''
active_executable_identity=''
active_variant=''
active_case=''
active_run=''
active_dir=''

read_process_identity() {
	local pid=$1
	[[ -r /proc/$pid/stat ]] || return 1
	awk '{ sub(/^.*\) /, ""); print $3, $4, $20, $1 }' "/proc/$pid/stat" 2>/dev/null
}

read_process_executable_identity() {
	local pid=$1
	stat -Lc '%d:%i' -- "/proc/$pid/exe" 2>/dev/null
}

record_active_process() {
	local selected_binary=$1 pid_file=$2
	local observed_pid observed_pgid observed_session observed_starttime observed_state attempt
	active_executable_identity=$(stat -Lc '%d:%i' -- "$selected_binary") || return 1
	for ((attempt = 0; attempt < 20; attempt++)); do
		observed_pid=''
		if [[ -r $pid_file ]]; then
			read -r observed_pid <"$pid_file" || true
		fi
		if [[ $observed_pid =~ ^[1-9][0-9]*$ ]]; then
			active_pid=$observed_pid
			if read -r observed_pgid observed_session observed_starttime observed_state < <(read_process_identity "$active_pid"); then
				if [[ $observed_state != Z && $observed_pgid == "$active_pid" && $observed_session == "$active_pid" && -n $observed_starttime ]]; then
					active_pgid=$observed_pgid
					active_starttime=$observed_starttime
					return 0
				fi
			fi
		fi
		sleep 0.05
	done
	return 1
}

active_process_instance_matches() {
	[[ -n $active_pid && -n $active_pgid && -n $active_starttime ]] || return 1
	local observed_pgid observed_session observed_starttime observed_state
	if ! read -r observed_pgid observed_session observed_starttime observed_state < <(read_process_identity "$active_pid"); then
		return 1
	fi
	[[ $observed_state != Z && $observed_pgid == "$active_pgid" && $observed_session == "$active_pgid" && $observed_starttime == "$active_starttime" ]]
}

active_process_matches() {
	active_process_instance_matches || return 1
	[[ -n $active_executable_identity ]] || return 1
	[[ $(read_process_executable_identity "$active_pid") == "$active_executable_identity" ]]
}

wait_for_selected_binary() {
	local attempt observed
	for ((attempt = 0; attempt < timeout_seconds * 20; attempt++)); do
		active_process_instance_matches || return 1
		observed=$(read_process_executable_identity "$active_pid") || return 1
		[[ $observed == "$active_executable_identity" ]] && return 0
		sleep 0.05
	done
	return 1
}

active_process_is_zombie() {
	[[ -n $active_pid && -n $active_pgid && -n $active_starttime ]] || return 1
	local observed_pgid observed_session observed_starttime observed_state
	if ! read -r observed_pgid observed_session observed_starttime observed_state < <(read_process_identity "$active_pid"); then
		return 1
	fi
	[[ $observed_state == Z && $observed_pgid == "$active_pgid" && $observed_session == "$active_pgid" && $observed_starttime == "$active_starttime" ]]
}

wait_for_active_exit() {
	local attempt
	for ((attempt = 0; attempt < 50; attempt++)); do
		active_process_instance_matches || return 0
		sleep 0.1
	done
	! active_process_instance_matches
}

active_process_group_exists() {
	[[ -n $active_pgid ]] && kill -0 -- "-$active_pgid" 2>/dev/null
}

wait_for_active_group_exit() {
	local attempt
	for ((attempt = 0; attempt < 50; attempt++)); do
		active_process_group_exists || return 0
		sleep 0.1
	done
	! active_process_group_exists
}

require_active_process() {
	local phase=$1
	if active_process_matches; then
		return 0
	fi
	printf 'udp-latency: measured process exited or changed identity after %s\n' "$phase" >&2
	return 1
}

stop_active_process() {
	local pid=$active_pid launcher_pid=$active_launcher_pid can_reap=0 rc=0
	if active_process_instance_matches; then
		# The only group we signal is the session and group created by our own setsid.
		kill -TERM -- "-$active_pgid" 2>/dev/null || true
		if ! wait_for_active_exit; then
			kill -KILL -- "-$active_pgid" 2>/dev/null || true
			if ! wait_for_active_exit; then
				printf 'udp-latency: measured process did not exit after SIGKILL\n' >&2
				rc=1
			else
				can_reap=1
			fi
		else
			# The leader may have exited before one of its children; its unreaped
			# process-group identity still fences this final containment signal.
			kill -KILL -- "-$active_pgid" 2>/dev/null || true
			can_reap=1
		fi
	elif active_process_is_zombie; then
		kill -TERM -- "-$active_pgid" 2>/dev/null || true
		kill -KILL -- "-$active_pgid" 2>/dev/null || true
		can_reap=1
	elif [[ -n $pid ]] && ! kill -0 "$pid" 2>/dev/null; then
		can_reap=1
	elif [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
		printf 'udp-latency: refusing to signal unexpected process group for PID %s\n' "$pid" >&2
		rc=1
	fi

	if ((can_reap)); then
		[[ -z $pid ]] || wait "$pid" 2>/dev/null || true
		if [[ -n $launcher_pid && $launcher_pid != "$pid" ]]; then
			wait "$launcher_pid" 2>/dev/null || true
		fi
		if ! wait_for_active_group_exit; then
			printf 'udp-latency: owned process group remains after cleanup\n' >&2
			rc=1
		fi
	elif [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
		printf 'udp-latency: refusing an unbounded wait for PID %s\n' "$pid" >&2
		rc=1
	elif active_process_group_exists; then
		printf 'udp-latency: owned process group remains after cleanup\n' >&2
		rc=1
	fi
	active_launcher_pid=''
	active_pid=''
	active_pgid=''
	active_starttime=''
	active_executable_identity=''
	return "$rc"
}

teardown_active() {
	local rc=0
	if [[ -n $active_dir ]]; then
		set_hook_context "$active_variant" "$active_case" "$active_run" "$active_dir" "$active_pid" "$active_pgid"
		if ! run_hook teardown "$teardown_hook" "$active_dir/teardown.out" \
			"$active_variant" "$active_case" "$active_run" "$active_dir" "$active_pid" "$active_pgid"; then
			rc=1
		fi
	fi
	if ! stop_active_process; then
		rc=1
	fi
	active_variant=''
	active_case=''
	active_run=''
	active_dir=''
	return "$rc"
}

cleanup() {
	local rc=$?
	set +e
	teardown_active
	[[ -z ${work_dir:-} ]] || rm -rf -- "$work_dir"
	exit "$rc"
}

emit_row() {
	local source_mode=$1 metadata=$2 measurements=$3 statistics=$4 variant=$5 case_name=$6 run_number=$7
	python3 - "$source_mode" "$metadata" "$measurements" "$statistics" "$variant" "$case_name" "$run_number" "$samples" "$offered_rate" <<'PY'
import json
import math
import sys

mode, metadata_path, measurements_path, statistics_path, variant, case, run, samples, offered_rate = sys.argv[1:]

try:
    with open(metadata_path, encoding="utf-8") as handle:
        metadata = json.load(handle)
    with open(measurements_path, encoding="utf-8") as handle:
        measurements = json.load(handle)
    with open(statistics_path, encoding="utf-8") as handle:
        statistics = json.load(handle)

    def selected(document):
        if mode == "fixture":
            per_variant = document[variant]
            return per_variant.get(case, per_variant["default"])
        return document

    measurement = selected(measurements)
    stats = selected(statistics)
    variant_meta = metadata[variant]
    latencies = measurement["latency_us"]
    sent = measurement["sent"]
    received = measurement["received"]
    cpu_pct = measurement["cpu_pct"]
    rss_kib = measurement["rss_kib"]
    fd_count = measurement["fd_count"]
    queue_drops = stats["queue_drops"]
    warm_hit = stats["warm_hit"]

    if not isinstance(latencies, list) or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in latencies):
        raise ValueError("latency_us must be an array of finite non-negative numbers")
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (sent, received, rss_kib, fd_count)):
        raise ValueError("sent, received, rss_kib, and fd_count must be non-negative integers")
    sample_count = int(samples)
    if sent != sample_count or received > sent or len(latencies) != received:
        raise ValueError("sent must equal samples and latency_us length must equal received")
    if isinstance(cpu_pct, bool) or not isinstance(cpu_pct, (int, float)) or not math.isfinite(cpu_pct) or cpu_pct < 0:
        raise ValueError("cpu_pct must be a finite non-negative number")
    expected_drops = {"queue_full", "capacity_rejections", "slow_permit_rejected"}
    if set(queue_drops) != expected_drops or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in queue_drops.values()):
        raise ValueError("queue_drops has an invalid schema")
    if set(warm_hit) != {"attempts", "successes"}:
        raise ValueError("warm_hit must contain attempts and successes")
    attempts, successes = warm_hit["attempts"], warm_hit["successes"]
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (attempts, successes)) or successes > attempts:
        raise ValueError("warm_hit counters are invalid")
    for key in ("commit", "binary_sha256"):
        if not isinstance(variant_meta[key], str) or not variant_meta[key]:
            raise ValueError(f"metadata {variant}.{key} is invalid")
    if not isinstance(metadata["kernel"], str) or not metadata["kernel"] or not isinstance(metadata["topology"], str) or not metadata["topology"]:
        raise ValueError("metadata kernel or topology is invalid")

    ordered = sorted(latencies)
    def nearest_rank(percentile):
        if not ordered:
            return None
        return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]

    row = {
        "schema_version": 1,
        "variant": variant,
        "commit": variant_meta["commit"],
        "binary_sha256": variant_meta["binary_sha256"],
        "kernel": metadata["kernel"],
        "topology": metadata["topology"],
        "case": case,
        "run": int(run),
        "samples": int(samples),
        "offered_rate": int(offered_rate),
        "sent": sent,
        "received": received,
        "latency_unit": "us",
        "p50": nearest_rank(0.50),
        "p95": nearest_rank(0.95),
        "p99": nearest_rank(0.99),
        "max": ordered[-1] if ordered else None,
        "loss": (sent - received) / sent,
        "cpu_pct": cpu_pct,
        "rss_kib": rss_kib,
        "fd_count": fd_count,
        "queue_drops": queue_drops,
        "warm_hit": {
            "attempts": attempts,
            "successes": successes,
            "rate": successes / attempts if attempts else None,
        },
    }
    print(json.dumps(row, separators=(",", ":"), allow_nan=False))
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    print(f"udp-latency: invalid measurement data: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

validate_fixture() {
	python3 - "$fixture_dir/meta.json" "$fixture_dir/samples.json" "$fixture_dir/stats.json" <<'PY'
import json
import re
import sys

meta_path, samples_path, stats_path = sys.argv[1:]
try:
    with open(meta_path, encoding="utf-8") as handle:
        meta = json.load(handle)
    with open(samples_path, encoding="utf-8") as handle:
        samples = json.load(handle)
    with open(stats_path, encoding="utf-8") as handle:
        stats = json.load(handle)
    if not isinstance(meta["kernel"], str) or not meta["kernel"] or not isinstance(meta["topology"], str) or not meta["topology"]:
        raise ValueError("meta kernel/topology")
    for variant in ("baseline", "candidate"):
        entry = meta[variant]
        if not isinstance(entry["commit"], str) or not re.fullmatch(r"[0-9a-fA-F]{7,64}", entry["commit"]):
            raise ValueError(f"meta {variant}.commit")
        if not isinstance(entry["binary_sha256"], str) or not re.fullmatch(r"[0-9a-fA-F]{64}", entry["binary_sha256"]):
            raise ValueError(f"meta {variant}.binary_sha256")
        if not isinstance(samples[variant]["default"], dict) or not isinstance(stats[variant]["default"], dict):
            raise ValueError(f"{variant} default fixture")
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    print(f"udp-latency: invalid fixture: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

build_live_metadata() {
	local topology_output="$work_dir/topology.json"
	set_hook_context '' '' '' "$work_dir" '' ''
	run_hook topology "$topology_hook" "$topology_output" "$work_dir" "$baseline_bin" "$candidate_bin" "$config_path"
	python3 - "$topology_output" "$(uname -r)" "$(sha256sum "$baseline_bin" | awk '{print $1}')" "$(sha256sum "$candidate_bin" | awk '{print $1}')" <<'PY' >"$work_dir/meta.json"
import json
import re
import sys

path, kernel, baseline_hash, candidate_hash = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as handle:
        topology = json.load(handle)
    output = {
        "kernel": kernel,
        "topology": topology["topology"],
        "baseline": {"commit": topology["baseline"]["commit"], "binary_sha256": baseline_hash},
        "candidate": {"commit": topology["candidate"]["commit"], "binary_sha256": candidate_hash},
    }
    if not isinstance(output["topology"], str) or not output["topology"]:
        raise ValueError("topology")
    for variant in ("baseline", "candidate"):
        commit = output[variant]["commit"]
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
            raise ValueError(f"{variant}.commit")
    print(json.dumps(output, separators=(",", ":")))
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    print(f"udp-latency: invalid topology hook output: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

run_live_measurement() {
	local variant=$1 case_name=$2 run_number=$3
	active_variant=$variant
	active_case=$case_name
	active_run=$run_number
	active_dir=$(mktemp -d "$work_dir/run.XXXXXX")
	local result_dir=$active_dir selected_binary
	case $variant in
	baseline) selected_binary=$baseline_bin ;;
	candidate) selected_binary=$candidate_bin ;;
	esac

	set_hook_context "$variant" "$case_name" "$run_number" "$active_dir" '' ''
	build_hook_environment
	local pid_file="$active_dir/session-leader.pid"
	setsid bash -c 'pid_file=$1; shift; printf "%s\n" "$$" >"$pid_file"; exec "$@"' \
		bash "$pid_file" env "${hook_environment[@]}" "$start_hook" "$variant" "$baseline_bin" "$candidate_bin" "$config_path" "$active_dir" \
		9>&- >"$active_dir/start.out" 2>"$active_dir/start.err" &
	active_launcher_pid=$!
	active_pid=$active_launcher_pid
	active_pgid=$active_launcher_pid
	active_starttime=''
	active_executable_identity=''

	local measurement_rc=0
	if ! record_active_process "$selected_binary" "$pid_file"; then
		printf 'udp-latency: start hook did not leave a live measured process\n' >&2
		measurement_rc=1
	elif ! wait_for_selected_binary; then
		printf 'udp-latency: start hook did not exec selected binary\n' >&2
		measurement_rc=1
	else
		set_hook_context "$variant" "$case_name" "$run_number" "$active_dir" "$active_pid" "$active_pgid"
		if ! run_hook ready "$ready_hook" "$active_dir/ready.out" "$variant" "$case_name" "$run_number" "$active_dir" "$active_pid" "$active_pgid"; then
			measurement_rc=1
		elif ! require_active_process 'ready'; then
			measurement_rc=1
		else
			set_hook_context "$variant" "$case_name" "$run_number" "$active_dir" "$active_pid" "$active_pgid"
			if ! run_hook setup "$setup_hook" "$active_dir/setup.out" "$variant" "$case_name" "$run_number" "$active_dir" "$active_pid" "$active_pgid"; then
				measurement_rc=1
			elif ! require_active_process 'setup'; then
				measurement_rc=1
			else
				set_hook_context "$variant" "$case_name" "$run_number" "$active_dir" "$active_pid" "$active_pgid"
				if ! run_hook probe "$probe_hook" "$active_dir/probe.json" "$variant" "$case_name" "$run_number" "$active_dir" "$active_pid" "$active_pgid"; then
					measurement_rc=1
				elif ! require_active_process 'probe'; then
					measurement_rc=1
				else
					set_hook_context "$variant" "$case_name" "$run_number" "$active_dir" "$active_pid" "$active_pgid"
					if ! run_hook stats "$stats_hook" "$active_dir/stats.json" "$variant" "$case_name" "$run_number" "$active_dir" "$active_pid" "$active_pgid"; then
						measurement_rc=1
					elif ! require_active_process 'stats'; then
						measurement_rc=1
					fi
				fi
			fi
		fi
	fi

	local teardown_rc=0
	if ! teardown_active; then
		teardown_rc=1
	fi
	if ((measurement_rc != 0 || teardown_rc != 0)); then
		return 1
	fi
	emit_row live "$work_dir/meta.json" "$result_dir/probe.json" "$result_dir/stats.json" "$variant" "$case_name" "$run_number"
}

baseline_bin=''
candidate_bin=''
config_path=''
echo_target=''
dns_target=''
samples=''
runs=''
offered_rate=''
fixture_dir=''
timeout_seconds=${HONK_UDP_TIMEOUT_SEC:-30}
start_hook=${HONK_UDP_START_HOOK:-}
ready_hook=${HONK_UDP_READY_HOOK:-}
setup_hook=${HONK_UDP_SETUP_HOOK:-}
probe_hook=${HONK_UDP_PROBE_HOOK:-}
stats_hook=${HONK_UDP_STATS_HOOK:-}
teardown_hook=${HONK_UDP_TEARDOWN_HOOK:-}
topology_hook=${HONK_UDP_TOPOLOGY_HOOK:-}
declare -A seen=()

while (($#)); do
	option=$1
	case $option in
	--help)
		[[ -z ${seen[--help]+x} ]] || die 'duplicate --help'
		seen[--help]=1
		shift
		;;
	--baseline-bin | --candidate-bin | --config | --echo-target | --dns-target | --samples | --runs | --offered-rate | --fixture | --timeout | --start-hook | --ready-hook | --setup-hook | --probe-hook | --stats-hook | --teardown-hook | --topology-hook)
		[[ -z ${seen[$option]+x} ]] || die "duplicate $option"
		(($# >= 2)) || die "$option requires a value"
		value=$2
		[[ $value != --* ]] || die "$option requires a value"
		seen[$option]=1
		case $option in
		--baseline-bin) baseline_bin=$value ;;
		--candidate-bin) candidate_bin=$value ;;
		--config) config_path=$value ;;
		--echo-target) echo_target=$value ;;
		--dns-target) dns_target=$value ;;
		--samples) samples=$value ;;
		--runs) runs=$value ;;
		--offered-rate) offered_rate=$value ;;
		--fixture) fixture_dir=$value ;;
		--timeout) timeout_seconds=$value ;;
		--start-hook) start_hook=$value ;;
		--ready-hook) ready_hook=$value ;;
		--setup-hook) setup_hook=$value ;;
		--probe-hook) probe_hook=$value ;;
		--stats-hook) stats_hook=$value ;;
		--teardown-hook) teardown_hook=$value ;;
		--topology-hook) topology_hook=$value ;;
		esac
		shift 2
		;;
	*) die "unknown argument: $option" ;;
	esac
done

if [[ -n ${seen[--help]+x} ]]; then
	((${#seen[@]} == 1)) || die '--help cannot be combined with other arguments'
	usage
	exit 0
fi

[[ -n $samples && -n $runs && -n $offered_rate ]] || die '--samples, --runs, and --offered-rate are required'
require_positive_integer --samples "$samples"
require_positive_integer --runs "$runs"
require_positive_integer --offered-rate "$offered_rate"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/honk-udp-latency.XXXXXX")
trap cleanup EXIT

if [[ -n $fixture_dir ]]; then
	[[ -z $baseline_bin && -z $candidate_bin && -z $config_path && -z $echo_target && -z $dns_target ]] || die '--fixture cannot be combined with live target or file arguments'
	for live_option in --timeout --start-hook --ready-hook --setup-hook --probe-hook --stats-hook --teardown-hook --topology-hook; do
		[[ -z ${seen[$live_option]+x} ]] || die '--fixture cannot be combined with live hooks'
	done
	[[ -d $fixture_dir ]] || die "fixture directory does not exist: $fixture_dir"
	for file in meta.json samples.json stats.json; do
		[[ -f $fixture_dir/$file && -r $fixture_dir/$file ]] || die "fixture file is missing or unreadable: $fixture_dir/$file"
	done
	validate_fixture
	for variant in baseline candidate; do
		for case_name in "${CASES[@]}"; do
			for ((run_number = 1; run_number <= runs; run_number++)); do
				emit_row fixture "$fixture_dir/meta.json" "$fixture_dir/samples.json" "$fixture_dir/stats.json" "$variant" "$case_name" "$run_number"
			done
		done
	done
	exit 0
fi

# Shell fixtures exercise the live hook lifecycle without network privileges.
# Production invocations remain root-only unless the test harness explicitly
# opts into this non-deployment escape hatch.
[[ $EUID -eq 0 || ${HONK_UDP_TEST_ALLOW_UNPRIVILEGED:-} == 1 ]] ||
	die 'live mode requires root'
[[ -n $baseline_bin && -n $candidate_bin && -n $config_path && -n $echo_target && -n $dns_target ]] || die 'live mode requires baseline/candidate binaries, config, echo target, and DNS target'
[[ -n $timeout_seconds && -n $start_hook && -n $ready_hook && -n $setup_hook && -n $probe_hook && -n $stats_hook && -n $teardown_hook && -n $topology_hook ]] || die 'live mode requires a timeout and every hook path'
require_positive_integer --timeout "$timeout_seconds"
require_executable_file --baseline-bin "$baseline_bin"
require_executable_file --candidate-bin "$candidate_bin"
[[ -f $config_path && -r $config_path ]] || die "--config must be a readable regular file: $config_path"
validate_target --echo-target "$echo_target"
validate_target --dns-target "$dns_target"
for hook_option in start ready setup probe stats teardown topology; do
	hook_variable="${hook_option}_hook"
	require_executable_file "--${hook_option}-hook" "${!hook_variable}"
done

# A deployment run mutates shared TPROXY/netns state. Fixture runs deliberately
# do not take this lock so they remain usable without root or host facilities.
exec 9>"$LOCK_FILE"
flock -n 9 || die "another UDP deployment benchmark holds $LOCK_FILE"
build_live_metadata

for variant in baseline candidate; do
	for case_name in "${CASES[@]}"; do
		for ((run_number = 1; run_number <= runs; run_number++)); do
			run_live_measurement "$variant" "$case_name" "$run_number"
		done
	done
done
