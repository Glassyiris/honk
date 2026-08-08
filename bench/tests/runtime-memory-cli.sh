#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
DRIVER="$ROOT/bench/runtime-memory.sh"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
export HONK_RUNTIME_MEMORY_LOCK_FILE="$TMP/runtime-memory.lock"
export PYTHONDONTWRITEBYTECODE=1

expect_fail() {
	local label=$1
	shift
	if "$@" >"$TMP/$label.out" 2>"$TMP/$label.err"; then
		printf '%s unexpectedly succeeded\n' "$label" >&2
		exit 1
	fi
}

python3 - "$TMP/fixture.json" <<'PY'
import json
import sys

path = sys.argv[1]
def metrics(pss):
    return {
        "rss_kib": pss + 10,
        "peak_rss_kib": pss + 20,
        "rss_anon_kib": pss,
        "rss_file_kib": 10,
        "threads": 4,
        "pss_kib": pss,
        "private_clean_kib": 0,
        "private_dirty_kib": pss - 10,
        "anonymous_kib": pss,
        "anon_huge_pages_kib": 0,
        "minor_faults": 50,
        "major_faults": 0,
        "cpu_ticks": 10,
        "start_time_ticks": 100,
        "fd_count": 8,
    }

def row(name, digest, pss):
    return {
        "schema_version": 2,
        "record": "runtime_memory",
        "scenario": "settled",
        "arm": name,
        "run": 99,
        "source_commit": ("1" if name == "baseline" else "2") * 40,
        "workload_path": "/fixture/runtime-memory-workload.py",
        "workload_sha256": "d" * 64,
        "driver_path": "/fixture/runtime-memory.sh",
        "driver_sha256": "e" * 64,
        "binary_path": f"/fixture/{name}",
        "binary_sha256": digest,
        "binary_size_bytes": 123,
        "binary_device": 1,
        "binary_inode": 2,
        "process_exe_device": 1,
        "process_exe_inode": 2,
        "pid": 42,
        "pid_start_time_ticks": 100,
        "config_path": "/fixture/config.dae",
        "config_sha256": "c" * 64,
        "config_device": 1,
        "config_inode": 3,
        "engine_log_path": f"/fixture/{name}.log",
        "rust_log": "info",
        "kernel": "fixture-kernel",
        "boot_id": "fixture-boot",
        "worker_threads": 16,
        "mi_collect_secs": 60,
        "target": "192.0.2.1",
        "netns": "fixture",
        "thp_enabled": "[always] madvise never",
        "cpu_governor": "performance",
        "turbo_disabled": 0,
        "direct_control_port": 5300,
        "direct_control_min_mbps": 8930,
        "churn_ports": [8001, 8002, 8003, 8004, 8005, 8006],
        "churn_count": 20000,
        "churn_concurrency": 64,
        "churn_batch_size": 2000,
        "churn_batch_pause": 1,
        "churn_retries": 3,
        "elapsed_seconds": 130,
        "rss_kib": pss + 10,
        "peak_rss_kib": pss + 20,
        "pss_kib": pss,
        "private_dirty_kib": pss - 10,
        "minor_faults": 50,
        "major_faults": 0,
        "minor_faults_delta": 5,
        "major_faults_delta": 0,
        "cpu_cores": 0.01,
        "throughput_mbps": 9000,
        "ops_per_s": 100,
        "p50_ms": 1,
        "p95_ms": 2,
        "p99_ms": 3,
        "samples": 1,
        "failures": 0,
        "loss": 0,
        "connections_before": 0,
        "connections_after": 0,
        "udp_stats_before": {"queue": {"full": 0}},
        "udp_stats_after": {"queue": {"full": 0}},
        "process_before": metrics(pss + 5),
        "process_after": metrics(pss),
        "curve": [{"second": 1, **metrics(pss)}],
    }
fixture = {
    "rows": {
        "baseline": [row("baseline", "a" * 64, 100)],
        "candidate": [row("candidate", "b" * 64, 80)],
    }
}
with open(path, "w", encoding="utf-8") as sink:
    json.dump(fixture, sink, sort_keys=True, separators=(",", ":"))
PY

"$DRIVER" --help >/dev/null
"$DRIVER" --fixture "$TMP/fixture.json" --runs 2 --output "$TMP/results.jsonl"

python3 - "$TMP/results.jsonl" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    rows = [json.loads(line) for line in source]
assert [(row["run"], row["arm"]) for row in rows] == [
    (1, "baseline"), (1, "candidate"), (2, "candidate"), (2, "baseline")
]
required = {
    "schema_version", "record", "binary_path", "binary_sha256", "binary_size_bytes",
    "binary_device", "binary_inode", "process_exe_device", "process_exe_inode",
    "pid", "pid_start_time_ticks", "config_path", "config_sha256", "config_device",
    "config_inode", "workload_sha256", "driver_sha256", "source_commit",
    "scenario", "run", "rss_kib", "peak_rss_kib", "pss_kib",
    "private_dirty_kib", "minor_faults", "major_faults", "cpu_cores",
    "throughput_mbps", "ops_per_s", "p50_ms", "p95_ms", "p99_ms", "samples",
    "failures", "loss", "connections_before", "connections_after",
    "udp_stats_before", "udp_stats_after", "process_before", "process_after", "curve",
    "direct_control_port", "direct_control_min_mbps", "churn_ports",
    "churn_count", "churn_concurrency", "churn_batch_size", "churn_batch_pause",
    "churn_retries",
}
assert all(required <= row.keys() for row in rows)
assert {row["binary_sha256"] for row in rows} == {"a" * 64, "b" * 64}
PY

python3 - "$ROOT/bench/runtime-memory-workload.py" "$TMP" <<'PY'
import argparse
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading

spec = importlib.util.spec_from_file_location("runtime_memory_workload", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with (Path(sys.argv[2]) / "fixture.json").open(encoding="utf-8") as source:
    template = json.load(source)["rows"]["baseline"][0]
direct = dict(template)
direct.pop("curve")
direct.update(
    scenario="direct_control",
    throughput_runs_mbps=[9000.0, 9010.0, 8990.0],
    active_process_metrics=template["process_after"],
    active_connections=1,
    active_samples=3,
    attempts=3,
    retries=0,
)
module.validate_row(direct)
protocol = dict(template)
protocol.pop("curve")
protocol.update(
    scenario="protocol_smoke",
    samples=36,
    throughput_mbps=0.0,
    ops_per_s=0.0,
    p50_ms=0.0,
    p95_ms=0.0,
    p99_ms=0.0,
    protocol_results=[
        {
            "network": "tcp" if index < 6 else "udp",
            "port": (8001 + index) if index < 6 else (53531 + index - 6),
            "samples": 3,
            "failures": 0,
        }
        for index in range(12)
    ],
)
module.validate_row(protocol)
try:
    module.parse_target("example.com")
except argparse.ArgumentTypeError:
    pass
else:
    raise AssertionError("hostname target was accepted")

log = Path(sys.argv[2]) / "reload.log"
log.write_text("SIGHUP reload request 7 applied\n", encoding="utf-8")
try:
    module.wait_reload_completion(log, os.getpid(), 0, timeout=0.05)
except TimeoutError:
    pass
else:
    raise AssertionError("completion without a SIGHUP receipt was accepted")
log.write_text(
    "SIGHUP reload request 7 received\nSIGHUP reload request 7 applied\n",
    encoding="utf-8",
)
module.wait_reload_completion(log, os.getpid(), 0, timeout=0.1)
binary = Path(sys.executable).resolve(strict=True)
binary_info = binary.stat()
binary_hash = module.sha256_file(binary)
process_start = module.process_metrics(os.getpid())["start_time_ticks"]
module.verify_pinned_binary(
    os.getpid(),
    process_start,
    binary,
    (binary_info.st_dev, binary_info.st_ino),
    binary_info.st_size,
    binary_hash,
)
try:
    module.verify_pinned_binary(
        os.getpid(),
        process_start,
        binary,
        (binary_info.st_dev, binary_info.st_ino),
        binary_info.st_size,
        "0" * 64,
    )
except RuntimeError:
    pass
else:
    raise AssertionError("binary hash replacement was accepted")

log.write_text(
    "Received SIGHUP, reloading configuration\nConfiguration applied\n",
    encoding="utf-8",
)
module.wait_reload_completion(log, os.getpid(), 0, timeout=0.1)
attempt_count = 0
async def flaky_request(*_):
    global attempt_count
    attempt_count += 1
    if attempt_count == 1:
        raise RuntimeError("connect timeout")
    return 0.001, 7

module.http_request = flaky_request
retry_result = asyncio.run(module.churn_client("192.0.2.1", 80, 2, 1, 1))
assert retry_result["successes"] == 2
assert retry_result["failures"] == 0
assert retry_result["attempts"] == 3
assert retry_result["retries"] == 1

observed_ports = []
async def record_port(_, port):
    observed_ports.append(port)
    return 0.001, 7

module.http_request = record_port
distributed = asyncio.run(
    module.churn_client("192.0.2.1", (8001, 8002, 8003), 6, 1, 0, 2, 0)
)
assert distributed["failures"] == 0
assert observed_ports == [8001, 8002, 8003, 8001, 8002, 8003]
assert distributed["batches"] == 3
assert module.retryable_http_error(asyncio.IncompleteReadError(b"", 1))
assert module.parse_ports("8001,8002,8003") == (8001, 8002, 8003)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = json.dumps({"connections": []}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    returncode, _, _, active = module.run_with_active_samples(
        [sys.executable, "-c", "import time; time.sleep(0.35)"],
        2,
        os.getpid(),
        f"http://127.0.0.1:{server.server_port}",
    )
    assert returncode == 0
    assert active["samples"] >= 2
    assert active["metrics"]["sample_monotonic"] > 0
finally:
    server.shutdown()
    thread.join()
PY

expect_fail reused-output "$DRIVER" --fixture "$TMP/fixture.json" --runs 1 --output "$TMP/results.jsonl"
expect_fail zero-runs "$DRIVER" --fixture "$TMP/fixture.json" --runs 0 --output "$TMP/zero.jsonl"
ln -s "$TMP/fixture.json" "$TMP/fixture-link.json"
expect_fail symlink-fixture "$DRIVER" --fixture "$TMP/fixture-link.json" --runs 1 --output "$TMP/link.jsonl"

expect_fail collect-overflow "$DRIVER" --fixture "$TMP/fixture.json" --runs 1 \
	--baseline-collect-secs 18446744073709551616 --output "$TMP/overflow.jsonl"
[[ ! -e $TMP/overflow.jsonl ]] || { printf 'overflow output was published\n' >&2; exit 1; }
python3 - "$TMP/fixture.json" "$TMP/invalid.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
del value["rows"]["baseline"][0]["throughput_mbps"]
with open(sys.argv[2], "w", encoding="utf-8") as sink:
    json.dump(value, sink)
PY
expect_fail invalid-schema "$DRIVER" --fixture "$TMP/invalid.json" --runs 1 --output "$TMP/invalid.jsonl"
python3 - "$TMP/fixture.json" "$TMP/invalid-version.json" "$TMP/invalid-record.json" "$TMP/invalid-identity.json" <<'PY'
import copy
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    fixture = json.load(source)
for path, field, value in (
    (sys.argv[2], "schema_version", 1),
    (sys.argv[3], "record", "other"),
    (sys.argv[4], "pid_start_time_ticks", None),
):
    changed = copy.deepcopy(fixture)
    if value is None:
        del changed["rows"]["baseline"][0][field]
    else:
        changed["rows"]["baseline"][0][field] = value
    with open(path, "w", encoding="utf-8") as sink:
        json.dump(changed, sink)
PY
expect_fail invalid-version "$DRIVER" --fixture "$TMP/invalid-version.json" --runs 1 \
	--output "$TMP/invalid-version.jsonl"
expect_fail invalid-record "$DRIVER" --fixture "$TMP/invalid-record.json" --runs 1 \
	--output "$TMP/invalid-record.jsonl"
expect_fail invalid-identity "$DRIVER" --fixture "$TMP/invalid-identity.json" --runs 1 \
	--output "$TMP/invalid-identity.jsonl"

python3 - "$TMP/fixture.json" "$TMP/late-invalid.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
del value["rows"]["candidate"][0]["throughput_mbps"]
with open(sys.argv[2], "w", encoding="utf-8") as sink:
    json.dump(value, sink)
PY
expect_fail late-invalid "$DRIVER" --fixture "$TMP/late-invalid.json" --runs 1 \
	--output "$TMP/late-invalid.jsonl"
[[ ! -e $TMP/late-invalid.jsonl ]] || { printf 'partial output was published\n' >&2; exit 1; }

printf 'runtime-memory CLI fixture tests passed\n'
