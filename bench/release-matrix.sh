#!/usr/bin/env bash
# Reproducible release-profile, target, and allocator benchmark matrix.
set -Eeuo pipefail
umask 077

readonly PROFILES=(release-size release-size-thin release-speed release-speed-thin)
readonly ARMS=(mimalloc-collect0 mimalloc-collect60 stock)
readonly SUPPORTED_TARGETS=(
	x86_64-unknown-linux-gnu
	x86_64-unknown-linux-musl
	aarch64-unknown-linux-gnu
	aarch64-unknown-linux-musl
)

output_dir=${HONK_RELEASE_BENCH_OUTPUT:-release-bench-results/$(date -u +%Y%m%dT%H%M%SZ)-$$}
benchmark_hook=${HONK_RELEASE_BENCH_HOOK:-}
runs=${HONK_RELEASE_BENCH_RUNS:-5}
warmup_runs=${HONK_RELEASE_BENCH_WARMUP_RUNS:-1}
base_features=${HONK_RELEASE_BENCH_FEATURES:-clash-api}
dry_run=false
all_targets=false
selected_profiles=()
selected_arms=()
selected_targets=()
metrics_file=''

usage() {
	cat <<'EOF'
Usage: release-matrix.sh [OPTIONS]

Builds the explicit size/speed x fat/thin release profiles and paired allocator
arms. Each cell has private Cargo target, workload cache, and run directories.

Options:
  --output DIR             Fresh result directory
  --profile NAME           Select a profile (repeatable; default: all)
  --arm NAME               Select an allocator arm (repeatable; default: all)
  --features LIST          Common comma-separated honk-core features
                           (default: clash-api; allocator is added by the arm)
  --target TRIPLE          Select a Linux target (repeatable; default: host)
  --all-targets            x86_64/aarch64 x gnu/musl build configuration matrix
  --benchmark-hook PATH    Executable workload/measurement hook
  --runs N                 Measured hook invocations per cell (default: 5)
  --warmup-runs N          Unrecorded hook invocations per cell (default: 1)
  --dry-run                Validate and write matrix JSONL/CSV without building
  -h, --help               Show this help

The hook runs with SELECTED_BIN, PROFILE, FEATURES, ALLOCATOR, COLLECT_SECS,
TARGET, RUN, WARMUP, MACHINE_JSON, OUTPUT_DIR, RUN_DIR, and CACHE_DIR. It must
print exactly one JSON object containing these non-negative numeric fields:
  rss_kib, pss_kib, private_dirty_kib, minor_faults, major_faults,
  cpu_user_seconds, cpu_system_seconds, cpu_percent,
  p50_us, p95_us, p99_us, collection_duration_seconds

Diagnostics belong on stderr. machine.json, matrix.jsonl/csv, builds.jsonl/csv,
and performance.jsonl/csv are machine-readable. A dry run is sufficient to
validate all four x86_64/aarch64 build configurations:
  bench/release-matrix.sh --all-targets --dry-run --output DIR
EOF
}

die() {
	printf 'release-matrix: %s\n' "$*" >&2
	exit 1
}

contains() {
	local needle=$1 value
	shift
	for value in "$@"; do
		[[ $value == "$needle" ]] && return 0
	done
	return 1
}

append_unique() {
	local value=$1 array_name=$2 item
	local -n values=$array_name
	for item in "${values[@]}"; do
		[[ $item == "$value" ]] && return
	done
	values+=("$value")
}

require_nonnegative_integer() {
	local name=$1 value=$2
	[[ $value =~ ^[0-9]+$ ]] || die "$name must be a non-negative integer"
}

cleanup() {
	[[ -z $metrics_file ]] || rm -f -- "$metrics_file"
}
trap cleanup EXIT

while (($#)); do
	case $1 in
	--output) (($# >= 2)) || die '--output requires a value'; output_dir=$2; shift 2 ;;
	--profile)
		(($# >= 2)) || die '--profile requires a value'
		contains "$2" "${PROFILES[@]}" || die "unknown profile: $2"
		append_unique "$2" selected_profiles
		shift 2
		;;
	--arm)
		(($# >= 2)) || die '--arm requires a value'
		contains "$2" "${ARMS[@]}" || die "unknown arm: $2"
		append_unique "$2" selected_arms
		shift 2
		;;
	--features) (($# >= 2)) || die '--features requires a value'; base_features=$2; shift 2 ;;
	--target)
		(($# >= 2)) || die '--target requires a value'
		contains "$2" "${SUPPORTED_TARGETS[@]}" || die "unsupported target: $2"
		append_unique "$2" selected_targets
		shift 2
		;;
	--all-targets) all_targets=true; shift ;;
	--benchmark-hook) (($# >= 2)) || die '--benchmark-hook requires a value'; benchmark_hook=$2; shift 2 ;;
	--runs) (($# >= 2)) || die '--runs requires a value'; runs=$2; shift 2 ;;
	--warmup-runs) (($# >= 2)) || die '--warmup-runs requires a value'; warmup_runs=$2; shift 2 ;;
	--dry-run) dry_run=true; shift ;;
	-h|--help) usage; exit 0 ;;
	*) die "unknown argument: $1" ;;
	esac
done

require_nonnegative_integer runs "$runs"
require_nonnegative_integer warmup-runs "$warmup_runs"
((runs > 0)) || die 'runs must be positive'
[[ -z $benchmark_hook || (-f $benchmark_hook && -x $benchmark_hook) ]] ||
	die "benchmark hook is not executable: $benchmark_hook"
[[ $base_features != *[[:space:]]* ]] ||
	die 'features must be a comma-separated list without whitespace'
[[ ",$base_features," != *,mimalloc,* ]] ||
	die 'mimalloc is controlled by --arm; omit it from --features'

((${#selected_profiles[@]})) || selected_profiles=("${PROFILES[@]}")
((${#selected_arms[@]})) || selected_arms=("${ARMS[@]}")
host_target=$(rustc -vV | sed -n 's/^host: //p')
contains "$host_target" "${SUPPORTED_TARGETS[@]}" ||
	die "host target $host_target is unsupported; pass --target explicitly"
if [[ $all_targets == true ]]; then
	((${#selected_targets[@]} == 0)) || die '--all-targets cannot be combined with --target'
	selected_targets=("${SUPPORTED_TARGETS[@]}")
elif ((${#selected_targets[@]} == 0)); then
	selected_targets=("$host_target")
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
if [[ -e $output_dir ]] && [[ -n $(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null) ]]; then
	die "output directory is not empty: $output_dir"
fi
output_dir=$(mkdir -p -- "$output_dir" && cd -- "$output_dir" && pwd -P)
cd -- "$repo_dir"

readonly machine_json="$output_dir/machine.json"
readonly matrix_jsonl="$output_dir/matrix.jsonl"
readonly matrix_csv="$output_dir/matrix.csv"
readonly builds_jsonl="$output_dir/builds.jsonl"
readonly builds_csv="$output_dir/builds.csv"
readonly performance_jsonl="$output_dir/performance.jsonl"
readonly performance_csv="$output_dir/performance.csv"

python3 - "$machine_json" "$repo_dir" <<'PY'
import json
import os
import platform
import subprocess
import sys

output, repo = sys.argv[1:]

def command(*args):
    try:
        return subprocess.run(
            args, cwd=repo, check=True, text=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"cannot collect {' '.join(args)} metadata: {error}") from error

def cpu_model():
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as source:
            for line in source:
                if line.lower().startswith("model name"):
                    return line.partition(":")[2].strip()
    except OSError:
        pass
    return platform.processor() or None

metadata = {
    "schema_version": 1,
    "hostname": platform.node(),
    "kernel": platform.release(),
    "os": platform.platform(),
    "architecture": platform.machine(),
    "cpu_model": cpu_model(),
    "logical_cpus": os.cpu_count(),
    "rustc": command("rustc", "--version", "--verbose"),
    "cargo": command("cargo", "--version", "--verbose"),
    "commit": command("git", "rev-parse", "HEAD"),
}
with open(output, "w", encoding="utf-8", newline="") as sink:
    json.dump(metadata, sink, sort_keys=True, separators=(",", ":"))
    sink.write("\n")
PY

profiles_joined=$(IFS=,; printf '%s' "${selected_profiles[*]}")
arms_joined=$(IFS=,; printf '%s' "${selected_arms[*]}")
targets_joined=$(IFS=,; printf '%s' "${selected_targets[*]}")
python3 - "$matrix_jsonl" "$matrix_csv" "$output_dir" "$profiles_joined" "$arms_joined" "$targets_joined" "$base_features" <<'PY'
import csv
import json
import os
import sys

json_path, csv_path, output, profiles, arms, targets, base_features = sys.argv[1:]
profiles = profiles.split(",")
arms = arms.split(",")
targets = targets.split(",")
rows = []
for target in targets:
    for profile in profiles:
        for arm in arms:
            allocator = "stock" if arm == "stock" else "mimalloc"
            collect_secs = None if arm == "stock" else int(arm.removeprefix("mimalloc-collect"))
            features = [item for item in base_features.split(",") if item]
            if allocator == "mimalloc":
                features.append("mimalloc")
            target_dir = os.path.join(output, "target", target, profile, arm)
            rows.append({
                "schema_version": 1,
                "record": "matrix",
                "target": target,
                "profile": profile,
                "features": features,
                "allocator": allocator,
                "collect_secs": collect_secs,
                "target_dir": target_dir,
                "cargo_arguments": [
                    "build", "--locked", "-p", "honk-core", "--bin", "honk-core",
                    "--profile", profile, "--no-default-features",
                    "--features", ",".join(features), "--target", target,
                ],
            })
with open(json_path, "w", encoding="utf-8", newline="") as sink:
    for row in rows:
        sink.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
with open(csv_path, "w", encoding="utf-8", newline="") as sink:
    fields = ["schema_version", "record", "target", "profile", "features", "allocator",
              "collect_secs", "target_dir", "cargo_arguments"]
    writer = csv.DictWriter(sink, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, "features": ",".join(row["features"]),
                         "cargo_arguments": json.dumps(row["cargo_arguments"], separators=(",", ":"))})
PY

: >"$builds_jsonl"
: >"$performance_jsonl"
if [[ $dry_run == true ]]; then
	printf 'dry-run matrix: %s\nmatrix csv: %s\nmachine metadata: %s\n' \
		"$matrix_jsonl" "$matrix_csv" "$machine_json"
	exit 0
fi

validate_metrics() {
	python3 - "$1" <<'PY'
import json
import math
import sys

path = sys.argv[1]
required = (
    "rss_kib", "pss_kib", "private_dirty_kib", "minor_faults", "major_faults",
    "cpu_user_seconds", "cpu_system_seconds", "cpu_percent",
    "p50_us", "p95_us", "p99_us", "collection_duration_seconds",
)
try:
    with open(path, encoding="utf-8") as source:
        metrics = json.load(source)
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"benchmark hook did not emit one valid JSON object: {error}") from error
if not isinstance(metrics, dict):
    raise SystemExit("benchmark hook output must be one JSON object")
missing = [key for key in required if key not in metrics]
if missing:
    raise SystemExit("benchmark hook metrics missing: " + ", ".join(missing))
for key in required:
    value = metrics[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SystemExit(f"benchmark hook metric {key} must be numeric")
    if not math.isfinite(value) or value < 0:
        raise SystemExit(f"benchmark hook metric {key} must be finite and non-negative")
for key in ("rss_kib", "pss_kib", "private_dirty_kib", "minor_faults", "major_faults"):
    if not isinstance(metrics[key], int):
        raise SystemExit(f"benchmark hook metric {key} must be an integer")
if not metrics["p50_us"] <= metrics["p95_us"] <= metrics["p99_us"]:
    raise SystemExit("benchmark hook latency percentiles must satisfy p50_us <= p95_us <= p99_us")
PY
}

for target in "${selected_targets[@]}"; do
	for profile in "${selected_profiles[@]}"; do
		for arm in "${selected_arms[@]}"; do
			case $arm in
			mimalloc-collect0) allocator=mimalloc; collect_secs=0 ;;
			mimalloc-collect60) allocator=mimalloc; collect_secs=60 ;;
			stock) allocator=stock; collect_secs=null ;;
			esac

			features=$base_features
			if [[ $allocator == mimalloc ]]; then
				if [[ -n $features ]]; then features+=,mimalloc; else features=mimalloc; fi
			fi
			target_dir="$output_dir/target/$target/$profile/$arm"
			build=(cargo build --locked -p honk-core --bin honk-core --profile "$profile" --no-default-features)
			[[ -z $features ]] || build+=(--features "$features")
			build+=(--target "$target")
			build_env=(env -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u SCCACHE_DIR)
			if [[ $target != "$host_target" ]]; then
				command -v zig >/dev/null ||
					die "zig is required to build non-host target $target"
				zig_target=${target/-unknown/}
				target_lower=${target//-/_}
				target_upper=${target^^}
				target_upper=${target_upper//-/_}
				bindgen_args=$(ci/zig-bindgen-env "$zig_target") ||
					die "cannot resolve zig headers for target $target"
				build_env+=(
					"ZIGCC_TARGET=$zig_target"
					"CC_$target_lower=$repo_dir/ci/zigcc"
					"CXX_$target_lower=$repo_dir/ci/zigcxx"
					"CARGO_TARGET_${target_upper}_LINKER=$repo_dir/ci/zigcc"
					"BINDGEN_EXTRA_CLANG_ARGS=$bindgen_args"
				)
				if [[ $target == *-musl ]]; then
					build_env+=("CARGO_TARGET_${target_upper}_RUSTFLAGS=-C link-self-contained=no")
				fi
			fi
			printf 'building target=%s profile=%s allocator=%s\n' "$target" "$profile" "$allocator" >&2
			if ! "${build_env[@]}" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$target_dir" "${build[@]}"; then
				die "build failed: target=$target profile=$profile arm=$arm (install the Rust target and required linker)"
			fi

			source_bin="$target_dir/$target/$profile/honk-core"
			[[ -f $source_bin && -x $source_bin ]] ||
				die "cargo did not produce an executable: $source_bin"
			artifact_dir="$output_dir/binaries/$target/$profile/$arm"
			mkdir -p -- "$artifact_dir"
			selected_bin="$artifact_dir/honk-core"
			cp -- "$source_bin" "$selected_bin"

			python3 - "$builds_jsonl" "$machine_json" "$selected_bin" "$profile" "$features" "$allocator" "$collect_secs" "$target" <<'PY'
import hashlib
import json
import os
import sys

out, machine_path, binary, profile, features, allocator, collect, target = sys.argv[1:]
with open(binary, "rb") as source:
    digest = hashlib.file_digest(source, "sha256").hexdigest()
with open(machine_path, encoding="utf-8") as source:
    machine = json.load(source)
row = {
    "schema_version": 1,
    "record": "build",
    "binary": os.path.realpath(binary),
    "binary_size_bytes": os.stat(binary).st_size,
    "binary_sha256": digest,
    "profile": profile,
    "features": [item for item in features.split(",") if item],
    "allocator": allocator,
    "collect_secs": None if collect == "null" else int(collect),
    "target": target,
    "machine": machine,
}
with open(out, "a", encoding="utf-8", newline="") as sink:
    sink.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
PY

			[[ -n $benchmark_hook ]] || continue
			for ((run = 1 - warmup_runs; run <= runs; run++)); do
				if ((run <= 0)); then
					warmup=true
					display_run=$((run + warmup_runs))
					run_kind=warmup
				else
					warmup=false
					display_run=$run
					run_kind=measured
				fi
				run_dir="$output_dir/runs/$target/$profile/$arm/$run_kind-$display_run"
				cache_dir="$output_dir/cache/$target/$profile/$arm/$run_kind-$display_run"
				mkdir -p -- "$run_dir" "$cache_dir"
				metrics_file=$(mktemp "$run_dir/metrics.XXXXXX")
				printf 'benchmarking target=%s profile=%s arm=%s %s=%s\n' \
					"$target" "$profile" "$arm" "$run_kind" "$display_run" >&2
				hook_env=(
					SELECTED_BIN="$selected_bin" PROFILE="$profile" FEATURES="$features"
					ALLOCATOR="$allocator" TARGET="$target" RUN="$display_run" WARMUP="$warmup"
					MACHINE_JSON="$machine_json" OUTPUT_DIR="$output_dir"
					RUN_DIR="$run_dir" CACHE_DIR="$cache_dir" XDG_CACHE_HOME="$cache_dir"
				)
				if [[ $collect_secs == null ]]; then
					if ! env -u HONK_MI_COLLECT_SECS "${hook_env[@]}" COLLECT_SECS='' \
						"$benchmark_hook" >"$metrics_file"; then
						die "benchmark hook failed: target=$target profile=$profile arm=$arm $run_kind=$display_run"
					fi
				elif ! env "${hook_env[@]}" COLLECT_SECS="$collect_secs" \
					HONK_MI_COLLECT_SECS="$collect_secs" "$benchmark_hook" >"$metrics_file"; then
					die "benchmark hook failed: target=$target profile=$profile arm=$arm $run_kind=$display_run"
				fi
				validate_metrics "$metrics_file" ||
					die "invalid benchmark metrics: target=$target profile=$profile arm=$arm $run_kind=$display_run"
				if [[ $warmup == true ]]; then
					rm -f -- "$metrics_file"
					metrics_file=''
					continue
				fi
				python3 - "$performance_jsonl" "$machine_json" "$metrics_file" "$selected_bin" "$profile" "$features" "$allocator" "$collect_secs" "$target" "$display_run" <<'PY'
import hashlib
import json
import os
import sys

out, machine_path, metrics_path, binary, profile, features, allocator, collect, target, run = sys.argv[1:]
with open(metrics_path, encoding="utf-8") as source:
    metrics = json.load(source)
with open(machine_path, encoding="utf-8") as source:
    machine = json.load(source)
with open(binary, "rb") as source:
    digest = hashlib.file_digest(source, "sha256").hexdigest()
row = {
    "schema_version": 1,
    "record": "performance",
    "run": int(run),
    "binary": os.path.realpath(binary),
    "binary_size_bytes": os.stat(binary).st_size,
    "binary_sha256": digest,
    "profile": profile,
    "features": [item for item in features.split(",") if item],
    "allocator": allocator,
    "collect_secs": None if collect == "null" else int(collect),
    "target": target,
    "machine": machine,
    "metrics": metrics,
}
with open(out, "a", encoding="utf-8", newline="") as sink:
    sink.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
PY
				rm -f -- "$metrics_file"
				metrics_file=''
			done
		done
	done
done

python3 - "$builds_jsonl" "$builds_csv" "$performance_jsonl" "$performance_csv" <<'PY'
import csv
import json
import sys

build_json, build_csv, performance_json, performance_csv = sys.argv[1:]

def rows(path):
    with open(path, encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]

build_fields = [
    "schema_version", "record", "target", "profile", "features", "allocator",
    "collect_secs", "binary", "binary_size_bytes", "binary_sha256",
]
with open(build_csv, "w", encoding="utf-8", newline="") as sink:
    writer = csv.DictWriter(sink, fieldnames=build_fields)
    writer.writeheader()
    for row in rows(build_json):
        writer.writerow({key: ",".join(row[key]) if key == "features" else row.get(key)
                         for key in build_fields})

metric_fields = [
    "rss_kib", "pss_kib", "private_dirty_kib", "minor_faults", "major_faults",
    "cpu_user_seconds", "cpu_system_seconds", "cpu_percent",
    "p50_us", "p95_us", "p99_us", "collection_duration_seconds",
]
performance_fields = build_fields + ["run"] + metric_fields
with open(performance_csv, "w", encoding="utf-8", newline="") as sink:
    writer = csv.DictWriter(sink, fieldnames=performance_fields)
    writer.writeheader()
    for row in rows(performance_json):
        flattened = {key: ",".join(row[key]) if key == "features" else row.get(key)
                     for key in build_fields + ["run"]}
        flattened.update({key: row["metrics"][key] for key in metric_fields})
        writer.writerow(flattened)
PY

printf 'machine metadata: %s\nmatrix: %s (%s)\nbuild metadata: %s (%s)\nperformance results: %s (%s)\n' \
	"$machine_json" "$matrix_jsonl" "$matrix_csv" "$builds_jsonl" "$builds_csv" \
	"$performance_jsonl" "$performance_csv"
