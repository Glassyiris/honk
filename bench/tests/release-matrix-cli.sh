#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
script="$repo_dir/bench/release-matrix.sh"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p -- "$tmp/bin"

cat >"$tmp/bin/rustc" <<'SH'
#!/usr/bin/env bash
if [[ ${1:-} == -vV ]]; then
	printf 'rustc 1.0.0 (fake)\nhost: x86_64-unknown-linux-gnu\n'
else
	printf 'rustc 1.0.0 (fake)\n'
fi
SH

cat >"$tmp/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ ${1:-} == --version ]]; then
	printf 'cargo 1.0.0 (fake)\n'
	exit 0
fi
[[ ${1:-} == build ]] || { printf 'unexpected cargo invocation: %s\n' "$*" >&2; exit 64; }
profile=''
target=''
while (($#)); do
	case $1 in
	--profile) profile=$2; shift 2 ;;
	--target) target=$2; shift 2 ;;
	*) shift ;;
	esac
done
[[ -n $profile && -n $target && -n ${CARGO_TARGET_DIR:-} ]] || exit 65
mkdir -p -- "$CARGO_TARGET_DIR/$target/$profile"
printf '#!/usr/bin/env bash\nexit 0\n' >"$CARGO_TARGET_DIR/$target/$profile/honk-core"
chmod +x "$CARGO_TARGET_DIR/$target/$profile/honk-core"
printf '%s|%s|%s|%s|%s\n' "$target" "$profile" "$CARGO_TARGET_DIR" "${CARGO_INCREMENTAL:-}" "${RUSTC_WRAPPER-unset}" >>"$FAKE_CARGO_LOG"
SH

cat >"$tmp/hook" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ -x $SELECTED_BIN && -d $RUN_DIR && -d $CACHE_DIR && $XDG_CACHE_HOME == "$CACHE_DIR" ]]
case $ALLOCATOR in
mimalloc) [[ $COLLECT_SECS == 60 && ${HONK_MI_COLLECT_SECS:-} == 60 ]] ;;
stock) [[ -z $COLLECT_SECS && ! -v HONK_MI_COLLECT_SECS ]] ;;
*) exit 66 ;;
esac
printf '%s|%s|%s|%s|%s\n' "$TARGET" "$PROFILE" "$ALLOCATOR" "$WARMUP" "$RUN" >>"$HOOK_LOG"
printf '%s\n' '{"rss_kib":100,"pss_kib":90,"private_dirty_kib":80,"minor_faults":7,"major_faults":1,"cpu_user_seconds":1.25,"cpu_system_seconds":0.5,"cpu_percent":75,"throughput_mbps":9000,"p50_us":10,"p95_us":20,"p99_us":30,"collection_duration_seconds":2.5}'
SH
chmod +x "$tmp/bin/rustc" "$tmp/bin/cargo" "$tmp/hook"

export PATH="$tmp/bin:$PATH"
export FAKE_CARGO_LOG="$tmp/cargo.log"
export HOOK_LOG="$tmp/hook.log"

"$script" --help >/dev/null
"$script" --all-targets --dry-run --output "$tmp/plan" >/dev/null
python3 - "$tmp/plan/matrix.jsonl" "$tmp/plan/matrix.csv" "$tmp/plan/machine.json" <<'PY'
import csv
import json
import sys

matrix_json, matrix_csv, machine_json = sys.argv[1:]
with open(matrix_json, encoding="utf-8") as source:
    rows = [json.loads(line) for line in source]
assert len(rows) == 48
assert {row["target"].split("-")[0] for row in rows} == {"x86_64", "aarch64"}
assert {row["profile"] for row in rows} == {
    "release-size", "release-size-thin", "release-speed", "release-speed-thin",
}
assert {row["allocator"] for row in rows} == {"mimalloc", "stock"}
assert len({row["target_dir"] for row in rows}) == 48
with open(matrix_csv, encoding="utf-8", newline="") as source:
    assert len(list(csv.DictReader(source))) == 48
with open(machine_json, encoding="utf-8") as source:
    machine = json.load(source)
assert "cpu_governors" in machine
assert "turbo_enabled" in machine
PY

"$script" \
	--profile release-speed-thin \
	--arm mimalloc-collect60 --arm stock \
	--target x86_64-unknown-linux-gnu \
	--benchmark-hook "$tmp/hook" --runs 2 --warmup-runs 1 \
	--output "$tmp/results" >/dev/null

python3 - "$tmp/results/builds.jsonl" "$tmp/results/builds.csv" \
	"$tmp/results/performance.jsonl" "$tmp/results/performance.csv" \
	"$tmp/cargo.log" "$tmp/hook.log" <<'PY'
import csv
import json
import os
import sys

build_json, build_csv, perf_json, perf_csv, cargo_log, hook_log = sys.argv[1:]
with open(build_json, encoding="utf-8") as source:
    builds = [json.loads(line) for line in source]
assert len(builds) == 2
assert {row["allocator"] for row in builds} == {"mimalloc", "stock"}
assert all(row["profile"] == "release-speed-thin" for row in builds)
assert all(row["binary_size_bytes"] > 0 and len(row["binary_sha256"]) == 64 for row in builds)
assert all(row["target"] == "x86_64-unknown-linux-gnu" for row in builds)
with open(build_csv, encoding="utf-8", newline="") as source:
    assert len(list(csv.DictReader(source))) == 2
with open(perf_json, encoding="utf-8") as source:
    performance = [json.loads(line) for line in source]
assert len(performance) == 4
required = {
    "rss_kib", "pss_kib", "private_dirty_kib", "minor_faults", "major_faults",
    "cpu_user_seconds", "cpu_system_seconds", "cpu_percent", "throughput_mbps",
    "p50_us", "p95_us", "p99_us", "collection_duration_seconds",
}
assert all(required <= row["metrics"].keys() for row in performance)
with open(perf_csv, encoding="utf-8", newline="") as source:
    csv_rows = list(csv.DictReader(source))
assert len(csv_rows) == 4
assert required <= csv_rows[0].keys()
with open(cargo_log, encoding="utf-8") as source:
    cargo_rows = [line.rstrip("\n").split("|") for line in source]
assert len(cargo_rows) == 2
assert len({row[2] for row in cargo_rows}) == 2
assert all(row[3:] == ["0", "unset"] for row in cargo_rows)
with open(hook_log, encoding="utf-8") as source:
    hook_rows = [line.rstrip("\n").split("|") for line in source]
assert len(hook_rows) == 6
assert sum(row[3] == "true" for row in hook_rows) == 2
assert sum(row[3] == "false" for row in hook_rows) == 4
cache_dirs = []
for root, dirs, _files in os.walk(os.path.join(os.path.dirname(perf_json), "cache")):
    cache_dirs.extend(os.path.join(root, item) for item in dirs if item.startswith(("warmup-", "measured-")))
assert len(cache_dirs) == 6 and len(set(cache_dirs)) == 6
PY

if "$script" --dry-run --output "$tmp/results" >"$tmp/reused.out" 2>"$tmp/reused.err"; then
	printf 'non-empty output directory unexpectedly accepted\n' >&2
	exit 1
fi
if ! grep -q 'output directory is not empty' "$tmp/reused.err"; then
	printf 'non-empty output failure was not explicit\n' >&2
	exit 1
fi
