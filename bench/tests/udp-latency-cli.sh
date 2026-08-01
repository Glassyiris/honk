#!/usr/bin/env bash
# Shell-level contract tests for the deterministic fixture and live-hook modes.
set -Eeuo pipefail
umask 077

CDPATH=''
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/bench/udp-latency.sh"
FIXTURE="$ROOT/bench/tests/fixtures/udp-latency"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/honk-udp-latency-test.XXXXXX")
STUBBORN_HELPER_FILE="$TMP/stubborn-helper.pid"

stop_stubborn_helper() {
	local helper_pid=''
	if [[ -r $STUBBORN_HELPER_FILE ]]; then
		read -r helper_pid <"$STUBBORN_HELPER_FILE" || true
		if [[ $helper_pid =~ ^[1-9][0-9]*$ ]]; then
			kill -KILL -- "-$helper_pid" 2>/dev/null || true
		fi
		rm -f -- "$STUBBORN_HELPER_FILE"
	fi
}

cleanup_test() {
	stop_stubborn_helper
	rm -rf -- "$TMP"
}
trap cleanup_test EXIT

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

expect_fail() {
	local name=$1
	shift
	if "$@" >"$TMP/$name.out" 2>"$TMP/$name.err"; then
		fail "$name unexpectedly succeeded"
	fi
	[[ ! -s "$TMP/$name.out" ]] || fail "$name wrote diagnostics to stdout"
}

expect_fail_contains() {
	local name=$1 expected=$2
	shift 2
	expect_fail "$name" "$@"
	if ! grep -Fq -- "$expected" "$TMP/$name.err"; then
		cat "$TMP/$name.err" >&2
		fail "$name did not report the expected validator: $expected"
	fi
}

assert_marker_process_gone() {
	local marker=$1 label=$2 pid pgid attempt
	[[ -s $marker ]] || fail "$label did not run teardown"
	read -r pid pgid <"$marker"
	[[ $pid =~ ^[1-9][0-9]*$ && $pgid =~ ^[1-9][0-9]*$ ]] ||
		fail "$label wrote an invalid teardown identity"
	for ((attempt = 0; attempt < 20; attempt++)); do
		if ! kill -0 "$pid" 2>/dev/null && ! kill -0 -- "-$pgid" 2>/dev/null; then
			return 0
		fi
		sleep 0.05
	done
	fail "$label left its measured process group alive"
}

# Help is the only non-JSON stdout mode.
help=$(bash "$SCRIPT" --help)
[[ "$help" == *'--fixture DIR'* ]] || fail 'help does not document --fixture'
[[ "$help" == *'--baseline-bin PATH'* ]] || fail 'help does not document fixed live arguments'
[[ "$help" == *'HONK_UDP_TIMEOUT_SEC'* ]] || fail 'help does not document the default timeout environment'
[[ "$help" == *'--preserve-env'* ]] || fail 'help does not document sudo environment preservation'

expect_fail unknown bash "$SCRIPT" --unknown
expect_fail missing bash "$SCRIPT" --fixture "$FIXTURE" --samples 5 --runs 2
expect_fail duplicate bash "$SCRIPT" --fixture "$FIXTURE" --samples 5 --runs 2 --offered-rate 1000 --runs 3
expect_fail invalid-samples bash "$SCRIPT" --fixture "$FIXTURE" --samples 0 --runs 2 --offered-rate 1000
expect_fail invalid-runs bash "$SCRIPT" --fixture "$FIXTURE" --samples 5 --runs nope --offered-rate 1000
expect_fail invalid-rate bash "$SCRIPT" --fixture "$FIXTURE" --samples 5 --runs 2 --offered-rate 1.5
expect_fail missing-fixture bash "$SCRIPT" --fixture "$TMP/nope" --samples 5 --runs 2 --offered-rate 1000
mkdir "$TMP/bad-fixture"
printf '{}\n' >"$TMP/bad-fixture/meta.json"
expect_fail bad-fixture bash "$SCRIPT" --fixture "$TMP/bad-fixture" --samples 5 --runs 2 --offered-rate 1000

bash "$SCRIPT" --fixture "$FIXTURE" --samples 5 --runs 2 --offered-rate 1000 >"$TMP/results.jsonl" 2>"$TMP/results.err"
python3 - "$TMP/results.jsonl" <<'PY'
import json
import sys

path = sys.argv[1]
rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
cases = [
    "cold_endpoint",
    "steady_hit",
    "warm_session_cold_endpoint",
    "dns_hit",
    "dns_miss",
    "healthy_candidate",
    "blackholed_candidate",
]
expected = [
    (variant, case, run)
    for variant in ("baseline", "candidate")
    for case in cases
    for run in (1, 2)
]
assert len(rows) == len(expected), (len(rows), len(expected))
assert [(r["variant"], r["case"], r["run"]) for r in rows] == expected
required = {
    "schema_version", "variant", "commit", "binary_sha256", "kernel", "topology", "case", "run",
    "samples", "offered_rate", "sent", "received", "latency_unit", "p50", "p95",
    "p99", "max", "loss", "cpu_pct", "rss_kib", "fd_count", "queue_drops", "warm_hit",
}
for row in rows:
    assert set(row) == required, row
    assert row["schema_version"] == 1
    assert isinstance(row["variant"], str)
    assert isinstance(row["commit"], str)
    assert isinstance(row["binary_sha256"], str) and len(row["binary_sha256"]) == 64
    assert isinstance(row["kernel"], str) and isinstance(row["topology"], str)
    assert isinstance(row["case"], str) and isinstance(row["run"], int)
    assert row["samples"] == 5 and row["offered_rate"] == 1000
    assert row["sent"] == row["samples"]
    assert isinstance(row["sent"], int) and isinstance(row["received"], int)
    assert row["latency_unit"] == "us"
    assert isinstance(row["loss"], (int, float)) and not isinstance(row["loss"], bool)
    assert isinstance(row["cpu_pct"], (int, float)) and not isinstance(row["cpu_pct"], bool)
    assert isinstance(row["rss_kib"], int) and isinstance(row["fd_count"], int)
    assert set(row["queue_drops"]) == {"queue_full", "capacity_rejections", "slow_permit_rejected"}
    assert all(isinstance(value, int) for value in row["queue_drops"].values())
    assert set(row["warm_hit"]) == {"attempts", "successes", "rate"}
    assert isinstance(row["warm_hit"]["attempts"], int)
    assert isinstance(row["warm_hit"]["successes"], int)
    assert row["warm_hit"]["rate"] is None or isinstance(row["warm_hit"]["rate"], (int, float))
    if row["variant"] == "candidate" and row["case"] == "blackholed_candidate":
        assert row["received"] == 0 and row["loss"] == 1
        assert all(row[key] is None for key in ("p50", "p95", "p99", "max"))
    else:
        assert row["received"] == row["sent"]
        assert all(isinstance(row[key], (int, float)) for key in ("p50", "p95", "p99", "max"))
        assert row["loss"] == 0
PY

cp -R "$FIXTURE" "$TMP/sent-mismatch-fixture"
python3 - "$TMP/sent-mismatch-fixture/samples.json" <<'PY'
import json
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
data["baseline"]["default"]["sent"] = 4
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
expect_fail sent-mismatch bash "$SCRIPT" --fixture "$TMP/sent-mismatch-fixture" --samples 5 --runs 1 --offered-rate 1000

# Hooks are executable files, never shell snippets. Every hook receives the
# documented environment contract; failures and timeouts must call teardown
# and must not emit synthetic rows. This test-only escape hatch keeps the
# contract suite unprivileged; production live runs remain root-only.
export HONK_UDP_TEST_ALLOW_UNPRIVILEGED=1
export HONK_UDP_LOCK_FILE="$TMP/udp-latency.lock"
mkdir "$TMP/hooks"
touch "$TMP/config.dae"
BASELINE_BIN="$TMP/baseline-bin"
CANDIDATE_BIN="$TMP/candidate-bin"
ZOMBIE_BASELINE_BIN="$TMP/zombie-baseline-bin"
ZOMBIE_CANDIDATE_BIN="$TMP/zombie-candidate-bin"
cp -- "$(command -v bash)" "$BASELINE_BIN"
cp -- "$(command -v bash)" "$CANDIDATE_BIN"
cp -- "$(command -v python3)" "$ZOMBIE_BASELINE_BIN"
cp -- "$(command -v python3)" "$ZOMBIE_CANDIDATE_BIN"
chmod 700 "$BASELINE_BIN" "$CANDIDATE_BIN" "$ZOMBIE_BASELINE_BIN" "$ZOMBIE_CANDIDATE_BIN"

HOOK_ASSERT="$TMP/assert-hook-env"
HOOK_LOG="$TMP/hook.log"
EXPECTED_CONFIG="$TMP/config.dae"
EXPECTED_ECHO_TARGET='benchmark.example.test:9000'
EXPECTED_DNS_TARGET='[::1]:53'
WRONG_BINARY=$(command -v bash)
export HOOK_ASSERT HOOK_LOG EXPECTED_CONFIG EXPECTED_ECHO_TARGET EXPECTED_DNS_TARGET WRONG_BINARY
cat >"$HOOK_ASSERT" <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail

require_context_keys() {
    local key
    for key in variant case run workdir pid pgid selected_bin baseline_bin candidate_bin config echo_target dns_target samples offered_rate timeout; do
        [[ ${!key+x} ]] || { printf 'missing hook environment: %s\n' "$key" >&2; exit 1; }
    done
}

assert_shared_context() {
    require_context_keys
    [[ $variant == baseline || $variant == candidate ]]
    case "$case" in
        cold_endpoint|steady_hit|warm_session_cold_endpoint|dns_hit|dns_miss|healthy_candidate|blackholed_candidate) ;;
        *) exit 1 ;;
    esac
    [[ $run == 1 && -d $workdir && $pid =~ ^[1-9][0-9]*$ && $pgid == "$pid" ]]
    case "$variant" in
        baseline) [[ $selected_bin == "$baseline_bin" ]] ;;
        candidate) [[ $selected_bin == "$candidate_bin" ]] ;;
    esac
    [[ $config == "$EXPECTED_CONFIG" ]]
    [[ $echo_target == "$EXPECTED_ECHO_TARGET" && $dns_target == "$EXPECTED_DNS_TARGET" ]]
    [[ $samples == 5 && $offered_rate == 1000 && $timeout == "$EXPECTED_TIMEOUT" ]]
}

assert_start_context() {
    require_context_keys
    [[ $variant == baseline || $variant == candidate ]]
    [[ -n $case && $run == 1 && -d $workdir ]]
    case "$variant" in
        baseline) [[ $selected_bin == "$baseline_bin" ]] ;;
        candidate) [[ $selected_bin == "$candidate_bin" ]] ;;
    esac
    [[ $config == "$EXPECTED_CONFIG" ]]
    [[ $echo_target == "$EXPECTED_ECHO_TARGET" && $dns_target == "$EXPECTED_DNS_TARGET" ]]
    [[ $samples == 5 && $offered_rate == 1000 && $timeout == "$EXPECTED_TIMEOUT" ]]
    [[ -z $pid && -z $pgid ]]
}

assert_topology_context() {
    require_context_keys
    [[ -z $variant && -z $case && -z $run && -z $selected_bin && -z $pid && -z $pgid ]]
    [[ -d $workdir && -n $baseline_bin && -n $candidate_bin ]]
    [[ $config == "$EXPECTED_CONFIG" ]]
    [[ $echo_target == "$EXPECTED_ECHO_TARGET" && $dns_target == "$EXPECTED_DNS_TARGET" ]]
    [[ $samples == 5 && $offered_rate == 1000 && $timeout == "$EXPECTED_TIMEOUT" ]]
}
HOOK
chmod 700 "$HOOK_ASSERT"

cat >"$TMP/hooks/start" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_start_context
printf 'start:%s:%s:%s:%s\n' "$variant" "$case" "$run" "$timeout" >>"$HOOK_LOG"
exec "$selected_bin" -c 'trap "exit 0" TERM INT; while :; do sleep 1; done'
HOOK
cat >"$TMP/hooks/start-wrong-binary" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_start_context
exec "$WRONG_BINARY" -c 'trap "exit 0" TERM INT; while :; do sleep 1; done'
HOOK
cat >"$TMP/hooks/start-exits" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_start_context
exit 0
HOOK
cat >"$TMP/hooks/start-held-zombie" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_start_context
exec "$selected_bin" - <<'PY'
import os
import signal
import time

if os.environ["variant"] == "baseline" and os.environ["case"] == "cold_endpoint":
    helper = os.fork()
    if helper == 0:
        zombie = os.fork()
        if zombie == 0:
            os._exit(0)
        os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        with open(os.environ["STUBBORN_HELPER_FILE"], "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
        while True:
            time.sleep(60)
    while not os.path.exists(os.environ["STUBBORN_HELPER_FILE"]):
        time.sleep(0.01)
while True:
    time.sleep(60)
PY
HOOK
cat >"$TMP/hooks/ready" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
printf 'ready:%s:%s:%s:%s\n' "$variant" "$case" "$run" "$timeout" >>"$HOOK_LOG"
HOOK
cat >"$TMP/hooks/ready-exits" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
kill -KILL "$pid"
sleep 0.05
HOOK
cat >"$TMP/hooks/setup" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
printf 'setup:%s:%s:%s:%s\n' "$variant" "$case" "$run" "$timeout" >>"$HOOK_LOG"
HOOK
cat >"$TMP/hooks/setup-kills-process" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
kill -KILL "$pid"
sleep 0.05
HOOK
cat >"$TMP/hooks/topology" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_topology_context
printf 'topology::::%s\n' "$timeout" >>"$HOOK_LOG"
printf '%s\n' '{"topology":"hook-test","baseline":{"commit":"be587b1"},"candidate":{"commit":"86a4f74"}}'
HOOK
cat >"$TMP/hooks/stats" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
printf 'stats:%s:%s:%s:%s\n' "$variant" "$case" "$run" "$timeout" >>"$HOOK_LOG"
printf '%s\n' '{"queue_drops":{"queue_full":0,"capacity_rejections":0,"slow_permit_rejected":0},"warm_hit":{"attempts":0,"successes":0}}'
HOOK
cat >"$TMP/hooks/teardown" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
printf 'teardown:%s:%s:%s:%s\n' "$variant" "$case" "$run" "$timeout" >>"$HOOK_LOG"
printf '%s %s\n' "$pid" "$pgid" >"${BENCH_TEST_MARKER:?}"
HOOK
cat >"$TMP/hooks/probe-fail" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
exit 7
HOOK
cat >"$TMP/hooks/probe-timeout" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
sleep 3
HOOK
cat >"$TMP/hooks/probe-success" <<'HOOK'
#!/usr/bin/env bash
source "${HOOK_ASSERT:?}"
assert_shared_context
printf 'probe:%s:%s:%s:%s\n' "$variant" "$case" "$run" "$timeout" >>"$HOOK_LOG"
printf '%s\n' '{"latency_us":[10,20,30,40,50],"sent":5,"received":5,"cpu_pct":1.5,"rss_kib":512,"fd_count":9}'
HOOK
chmod 700 "$TMP/hooks"/*

live_core_args=(
	--baseline-bin "$BASELINE_BIN" --candidate-bin "$CANDIDATE_BIN" --config "$TMP/config.dae"
	--echo-target "$EXPECTED_ECHO_TARGET" --dns-target "$EXPECTED_DNS_TARGET"
	--samples 5 --runs 1 --offered-rate 1000
)
expect_fail missing-live-hooks env \
	-u HONK_UDP_START_HOOK -u HONK_UDP_READY_HOOK -u HONK_UDP_SETUP_HOOK \
	-u HONK_UDP_PROBE_HOOK -u HONK_UDP_STATS_HOOK -u HONK_UDP_TEARDOWN_HOOK \
	-u HONK_UDP_TOPOLOGY_HOOK bash "$SCRIPT" "${live_core_args[@]}"

live_args=(
	"${live_core_args[@]}" --timeout 1
	--start-hook "$TMP/hooks/start" --ready-hook "$TMP/hooks/ready"
	--setup-hook "$TMP/hooks/setup" --stats-hook "$TMP/hooks/stats"
	--teardown-hook "$TMP/hooks/teardown" --topology-hook "$TMP/hooks/topology"
)
export EXPECTED_TIMEOUT=1
validator_args=(
	"${live_core_args[@]}" --timeout 1
	--start-hook "$TMP/hooks/start" --ready-hook "$TMP/hooks/ready"
	--setup-hook "$TMP/hooks/setup" --probe-hook "$TMP/hooks/probe-success"
	--stats-hook "$TMP/hooks/stats" --teardown-hook "$TMP/hooks/teardown"
	--topology-hook "$TMP/hooks/topology"
)
expect_fail_contains invalid-target '--echo-target is invalid' bash "$SCRIPT" \
	"${validator_args[@]/$EXPECTED_ECHO_TARGET/not-an-address}"
expect_fail_contains missing-binary '--baseline-bin must be an executable regular file' bash "$SCRIPT" \
	--baseline-bin "$TMP/nope" --candidate-bin "$CANDIDATE_BIN" --config "$EXPECTED_CONFIG" \
	--echo-target "$EXPECTED_ECHO_TARGET" --dns-target "$EXPECTED_DNS_TARGET" \
	--samples 5 --runs 1 --offered-rate 1000 --timeout 1 \
	--start-hook "$TMP/hooks/start" --ready-hook "$TMP/hooks/ready" \
	--setup-hook "$TMP/hooks/setup" --probe-hook "$TMP/hooks/probe-success" \
	--stats-hook "$TMP/hooks/stats" --teardown-hook "$TMP/hooks/teardown" \
	--topology-hook "$TMP/hooks/topology"
expect_fail_contains missing-config '--config must be a readable regular file' bash "$SCRIPT" \
	--baseline-bin "$BASELINE_BIN" --candidate-bin "$CANDIDATE_BIN" --config "$TMP/nope" \
	--echo-target "$EXPECTED_ECHO_TARGET" --dns-target "$EXPECTED_DNS_TARGET" \
	--samples 5 --runs 1 --offered-rate 1000 --timeout 1 \
	--start-hook "$TMP/hooks/start" --ready-hook "$TMP/hooks/ready" \
	--setup-hook "$TMP/hooks/setup" --probe-hook "$TMP/hooks/probe-success" \
	--stats-hook "$TMP/hooks/stats" --teardown-hook "$TMP/hooks/teardown" \
	--topology-hook "$TMP/hooks/topology"

BENCH_TEST_MARKER="$TMP/probe-fail-torn-down" expect_fail probe-failure \
	env BENCH_TEST_MARKER="$TMP/probe-fail-torn-down" HONK_UDP_TIMEOUT_SEC=9 bash "$SCRIPT" "${live_args[@]}" --probe-hook "$TMP/hooks/probe-fail"
assert_marker_process_gone "$TMP/probe-fail-torn-down" 'probe failure'
BENCH_TEST_MARKER="$TMP/probe-timeout-torn-down" expect_fail probe-timeout \
	env BENCH_TEST_MARKER="$TMP/probe-timeout-torn-down" HONK_UDP_TIMEOUT_SEC=9 bash "$SCRIPT" "${live_args[@]}" --probe-hook "$TMP/hooks/probe-timeout"
assert_marker_process_gone "$TMP/probe-timeout-torn-down" 'probe timeout'
BENCH_TEST_MARKER="$TMP/start-exit-torn-down" expect_fail start-exit \
	env BENCH_TEST_MARKER="$TMP/start-exit-torn-down" bash "$SCRIPT" "${live_core_args[@]}" --timeout 1 \
	--start-hook "$TMP/hooks/start-exits" --ready-hook "$TMP/hooks/ready" \
	--setup-hook "$TMP/hooks/setup" --probe-hook "$TMP/hooks/probe-success" \
	--stats-hook "$TMP/hooks/stats" --teardown-hook "$TMP/hooks/teardown" --topology-hook "$TMP/hooks/topology"
assert_marker_process_gone "$TMP/start-exit-torn-down" 'start exit'
BENCH_TEST_MARKER="$TMP/wrong-binary-torn-down" expect_fail_contains wrong-binary 'did not exec selected binary' \
	env BENCH_TEST_MARKER="$TMP/wrong-binary-torn-down" bash "$SCRIPT" "${live_core_args[@]}" --timeout 1 \
	--start-hook "$TMP/hooks/start-wrong-binary" --ready-hook "$TMP/hooks/ready" \
	--setup-hook "$TMP/hooks/setup" --probe-hook "$TMP/hooks/probe-success" \
	--stats-hook "$TMP/hooks/stats" --teardown-hook "$TMP/hooks/teardown" --topology-hook "$TMP/hooks/topology"
assert_marker_process_gone "$TMP/wrong-binary-torn-down" 'wrong executable'
BENCH_TEST_MARKER="$TMP/ready-exit-torn-down" expect_fail ready-exit \
	env BENCH_TEST_MARKER="$TMP/ready-exit-torn-down" bash "$SCRIPT" "${live_core_args[@]}" --timeout 1 \
	--start-hook "$TMP/hooks/start" --ready-hook "$TMP/hooks/ready-exits" \
	--setup-hook "$TMP/hooks/setup" --probe-hook "$TMP/hooks/probe-success" \
	--stats-hook "$TMP/hooks/stats" --teardown-hook "$TMP/hooks/teardown" --topology-hook "$TMP/hooks/topology"
assert_marker_process_gone "$TMP/ready-exit-torn-down" 'ready exit'
BENCH_TEST_MARKER="$TMP/setup-exit-torn-down" expect_fail_contains setup-exit 'process exited or changed identity after setup' \
	env BENCH_TEST_MARKER="$TMP/setup-exit-torn-down" bash "$SCRIPT" "${live_core_args[@]}" --timeout 1 \
	--start-hook "$TMP/hooks/start" --ready-hook "$TMP/hooks/ready" \
	--setup-hook "$TMP/hooks/setup-kills-process" --probe-hook "$TMP/hooks/probe-success" \
	--stats-hook "$TMP/hooks/stats" --teardown-hook "$TMP/hooks/teardown" --topology-hook "$TMP/hooks/topology"
assert_marker_process_gone "$TMP/setup-exit-torn-down" 'post-setup process exit'

held_group_marker="$TMP/held-zombie-torn-down"
expect_fail_contains held-zombie-group 'owned process group remains after cleanup' \
	env STUBBORN_HELPER_FILE="$STUBBORN_HELPER_FILE" BENCH_TEST_MARKER="$held_group_marker" bash "$SCRIPT" \
	--baseline-bin "$ZOMBIE_BASELINE_BIN" --candidate-bin "$ZOMBIE_CANDIDATE_BIN" --config "$EXPECTED_CONFIG" \
	--echo-target "$EXPECTED_ECHO_TARGET" --dns-target "$EXPECTED_DNS_TARGET" \
	--samples 5 --runs 1 --offered-rate 1000 --timeout 1 \
	--start-hook "$TMP/hooks/start-held-zombie" --ready-hook "$TMP/hooks/ready" \
	--setup-hook "$TMP/hooks/setup" --probe-hook "$TMP/hooks/probe-success" \
	--stats-hook "$TMP/hooks/stats" --teardown-hook "$TMP/hooks/teardown" \
	--topology-hook "$TMP/hooks/topology"
stop_stubborn_helper
assert_marker_process_gone "$held_group_marker" 'held zombie cleanup'

: >"$HOOK_LOG"
BENCH_TEST_MARKER="$TMP/probe-success-torn-down" HONK_UDP_TIMEOUT_SEC=9 bash "$SCRIPT" "${live_args[@]}" --probe-hook "$TMP/hooks/probe-success" >"$TMP/live.jsonl" 2>"$TMP/live.err"
assert_marker_process_gone "$TMP/probe-success-torn-down" 'successful live run'
python3 - "$TMP/live.jsonl" "$HOOK_LOG" <<'PY'
import json
import sys

rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
assert len(rows) == 14
assert all(row["schema_version"] == 1 and row["sent"] == 5 and row["received"] == 5 and row["p95"] == 50 for row in rows)
lines = [line.strip().split(":") for line in open(sys.argv[2], encoding="utf-8") if line.strip()]
assert len(lines) == 1 + 14 * 6, len(lines)
assert lines[0] == ["topology", "", "", "", "1"], lines[0]
for label in ("start", "ready", "setup", "probe", "stats", "teardown"):
    assert sum(parts[0] == label for parts in lines) == 14, label
assert all(parts[-1] == "1" for parts in lines)
PY

# The exact fixed command may omit timeout and hook flags when root's
# environment supplies them. The default timeout is 30 seconds.
: >"$HOOK_LOG"
export EXPECTED_TIMEOUT=30
BENCH_TEST_MARKER="$TMP/default-env-torn-down" \
	HONK_UDP_START_HOOK="$TMP/hooks/start" \
	HONK_UDP_READY_HOOK="$TMP/hooks/ready" \
	HONK_UDP_SETUP_HOOK="$TMP/hooks/setup" \
	HONK_UDP_PROBE_HOOK="$TMP/hooks/probe-success" \
	HONK_UDP_STATS_HOOK="$TMP/hooks/stats" \
	HONK_UDP_TEARDOWN_HOOK="$TMP/hooks/teardown" \
	HONK_UDP_TOPOLOGY_HOOK="$TMP/hooks/topology" \
	bash "$SCRIPT" "${live_core_args[@]}" >"$TMP/default-env.jsonl" 2>"$TMP/default-env.err"
assert_marker_process_gone "$TMP/default-env-torn-down" 'environment-configured live run'
python3 - "$TMP/default-env.jsonl" "$HOOK_LOG" <<'PY'
import json
import sys

rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
assert len(rows) == 14
assert all(row["schema_version"] == 1 and row["sent"] == 5 for row in rows)
assert all(line.rstrip().endswith(":30") for line in open(sys.argv[2], encoding="utf-8") if line.strip())
PY

printf 'udp-latency CLI fixture tests passed\n'
