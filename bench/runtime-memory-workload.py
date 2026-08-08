#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import statistics
import subprocess
import sys
import time
import urllib.request

REQUIRED_NUMERIC = (
    "rss_kib",
    "peak_rss_kib",
    "pss_kib",
    "private_dirty_kib",
    "minor_faults",
    "major_faults",
    "cpu_cores",
    "throughput_mbps",
    "ops_per_s",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "samples",
    "failures",
    "loss",
    "connections_before",
    "connections_after",
)
PROCESS_METRICS_NUMERIC = (
    "rss_kib",
    "peak_rss_kib",
    "rss_anon_kib",
    "rss_file_kib",
    "threads",
    "pss_kib",
    "private_clean_kib",
    "private_dirty_kib",
    "anonymous_kib",
    "anon_huge_pages_kib",
    "minor_faults",
    "major_faults",
    "cpu_ticks",
    "start_time_ticks",
    "fd_count",
)

COMMON_STRING_FIELDS = (
    "scenario",
    "arm",
    "source_commit",
    "workload_path",
    "workload_sha256",
    "driver_path",
    "driver_sha256",
    "binary_path",
    "binary_sha256",
    "config_path",
    "config_sha256",
    "engine_log_path",
    "rust_log",
    "kernel",
    "boot_id",
    "target",
    "netns",
    "thp_enabled",
    "cpu_governor",
)
PROTOCOL_TCP_PORTS = (8001, 8002, 8003, 8004, 8005, 8006)
PROTOCOL_UDP_PORTS = (53531, 53532, 53533, 53534, 53535, 53536)
CHURN_PORTS = PROTOCOL_TCP_PORTS


def require_nonnegative_number(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be finite and non-negative")


def validate_process_metrics(value: object, label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    for key in PROCESS_METRICS_NUMERIC:
        require_nonnegative_number(value.get(key), f"{label}.{key}")



def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()

def read_optional_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "unavailable"


def read_optional_int(path: str) -> int | None:
    value = read_optional_text(path)
    return int(value) if value != "unavailable" else None


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))]


def parse_target(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as error:
        raise argparse.ArgumentTypeError("target must be an IP address") from error

def parse_ports(raw: str) -> tuple[int, ...]:
    try:
        ports = tuple(int(value) for value in raw.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("ports must be comma-separated integers") from error
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise argparse.ArgumentTypeError("ports must be in 1..65535")
    return ports


def read_proc_stat(pid: int) -> tuple[list[str], str]:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    end = raw.rfind(")")
    if end < 0:
        raise RuntimeError("malformed process stat")
    return raw[end + 2 :].split(), raw[: end + 1]


def process_metrics(pid: int) -> dict[str, int]:
    status: dict[str, int] = {}
    with Path(f"/proc/{pid}/status").open(encoding="utf-8") as source:
        for line in source:
            key, _, value = line.partition(":")
            if key in {"VmRSS", "VmHWM", "Threads", "RssAnon", "RssFile"}:
                status[key] = int(value.split()[0])
    smaps: dict[str, int] = {}
    with Path(f"/proc/{pid}/smaps_rollup").open(encoding="utf-8") as source:
        for line in source:
            key, _, value = line.partition(":")
            if key in {"Rss", "Pss", "Private_Clean", "Private_Dirty", "Anonymous", "AnonHugePages"}:
                smaps[key] = int(value.split()[0])
    fields, _ = read_proc_stat(pid)
    return {
        "rss_kib": status["VmRSS"],
        "peak_rss_kib": status["VmHWM"],
        "rss_anon_kib": status["RssAnon"],
        "rss_file_kib": status["RssFile"],
        "threads": status["Threads"],
        "pss_kib": smaps["Pss"],
        "private_clean_kib": smaps["Private_Clean"],
        "private_dirty_kib": smaps["Private_Dirty"],
        "anonymous_kib": smaps["Anonymous"],
        "anon_huge_pages_kib": smaps["AnonHugePages"],
        "minor_faults": int(fields[7]),
        "major_faults": int(fields[9]),
        "cpu_ticks": int(fields[11]) + int(fields[12]),
        "start_time_ticks": int(fields[19]),
        "fd_count": len(tuple(Path(f"/proc/{pid}/fd").iterdir())),
    }


def executable_identity(path: Path) -> tuple[int, int]:
    info = path.stat()
    return info.st_dev, info.st_ino


def api_json(controller: str, endpoint: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(controller.rstrip("/") + endpoint, timeout=timeout) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError(f"API {endpoint} did not return an object")
    return value


def connection_count(controller: str) -> int:
    value = api_json(controller, "/connections")
    connections = value.get("connections")
    if not isinstance(connections, list):
        raise RuntimeError("connections API has an invalid schema")
    return len(connections)


def udp_stats(controller: str) -> dict:
    value = api_json(controller, "/stats")
    udp = value.get("udp")
    if not isinstance(udp, dict):
        raise RuntimeError("stats API has no UDP object")
    return udp


def verify_process_identity(pid: int, start_time: int, binary_identity: tuple[int, int]) -> None:
    metrics = process_metrics(pid)
    if metrics["start_time_ticks"] != start_time:
        raise RuntimeError("measured process identity changed")
    if executable_identity(Path(f"/proc/{pid}/exe")) != binary_identity:
        raise RuntimeError("measured process executable changed")


def verify_pinned_binary(
    pid: int,
    start_time: int,
    binary: Path,
    expected_identity: tuple[int, int],
    expected_size: int,
    expected_hash: str,
) -> None:
    verify_process_identity(pid, start_time, expected_identity)
    for label, path in (("selected", binary), ("measured", Path(f"/proc/{pid}/exe"))):
        if executable_identity(path) != expected_identity:
            raise RuntimeError(f"{label} binary identity changed")
        if path.stat().st_size != expected_size:
            raise RuntimeError(f"{label} binary size changed")
        if sha256_file(path) != expected_hash:
            raise RuntimeError(f"{label} binary hash changed")


async def http_request(host: str, port: int, path: str = "/") -> tuple[float, int]:
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    except asyncio.TimeoutError as error:
        raise RuntimeError("connect timeout") from error
    try:
        writer.write(
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        except asyncio.TimeoutError as error:
            raise RuntimeError("response header timeout") from error
        fields = {}
        for line in header.split(b"\r\n")[1:]:
            name, separator, value = line.partition(b":")
            if separator:
                fields[name.strip().lower()] = value.strip()
        try:
            content_length = int(fields[b"content-length"])
        except (KeyError, ValueError) as error:
            raise RuntimeError("response has no valid Content-Length") from error
        if not 0 <= content_length <= 1 << 20:
            raise RuntimeError(f"invalid Content-Length: {content_length}")
        try:
            payload = await asyncio.wait_for(reader.readexactly(content_length), 20)
        except asyncio.TimeoutError as error:
            raise RuntimeError("response body timeout") from error
        response_size = len(header) + len(payload)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    if not header.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")):
        raise RuntimeError(f"bad HTTP response: {header[:64]!r}")
    return time.monotonic() - started, response_size


def retryable_http_error(error: Exception) -> bool:
    return isinstance(error, (ConnectionError, asyncio.IncompleteReadError)) or (
        isinstance(error, RuntimeError)
        and str(error) in {"connect timeout", "response header timeout", "response body timeout"}
    )


async def churn_client(
    host: str,
    ports: int | tuple[int, ...],
    count: int,
    concurrency: int,
    connect_retries: int,
    batch_size: int | None = None,
    batch_pause: float = 0.0,
) -> dict:
    if isinstance(ports, int):
        ports = (ports,)
    if not ports:
        raise ValueError("churn requires at least one port")
    if count <= 0 or concurrency <= 0:
        raise ValueError("churn count and concurrency must be positive")
    if connect_retries < 0:
        raise ValueError("connect retries must be nonnegative")
    if batch_size is None:
        batch_size = count
    if batch_size <= 0 or batch_pause < 0:
        raise ValueError("batch size must be positive and pause nonnegative")

    latencies: list[float] = []
    failures: list[str] = []
    transferred = 0
    retries = 0

    async def run_batch(start: int, stop: int) -> None:
        queue: asyncio.Queue[int] = asyncio.Queue()
        for index in range(start, stop):
            queue.put_nowait(index)

        async def worker() -> None:
            nonlocal transferred, retries
            while True:
                try:
                    operation = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                operation_started = time.monotonic()
                try:
                    for attempt in range(connect_retries + 1):
                        try:
                            _, size = await http_request(host, ports[operation % len(ports)])
                            break
                        except Exception as error:
                            if not retryable_http_error(error) or attempt == connect_retries:
                                raise
                            retries += 1
                    latencies.append(time.monotonic() - operation_started)
                    transferred += size
                except Exception as error:
                    failures.append(f"{type(error).__name__}:{error}")
                finally:
                    queue.task_done()

        await asyncio.gather(*(worker() for _ in range(concurrency)))

    started = time.monotonic()
    batches = math.ceil(count / batch_size)
    for batch_index, batch_start in enumerate(range(0, count, batch_size)):
        await run_batch(batch_start, min(count, batch_start + batch_size))
        if batch_index + 1 < batches and batch_pause:
            await asyncio.sleep(batch_pause)
    elapsed = time.monotonic() - started
    latency_ms = [value * 1000 for value in latencies]
    return {
        "ops": count,
        "attempts": count + retries,
        "retries": retries,
        "successes": len(latencies),
        "failures": len(failures),
        "failure_examples": failures[:5],
        "elapsed_s": elapsed,
        "ops_per_s": len(latencies) / elapsed if elapsed else 0.0,
        "p50_ms": percentile(latency_ms, 0.50),
        "p95_ms": percentile(latency_ms, 0.95),
        "p99_ms": percentile(latency_ms, 0.99),
        "bytes": transferred,
        "throughput_mbps": transferred * 8 / elapsed / 1_000_000 if elapsed else 0.0,
        "batches": batches,
        "batch_size": batch_size,
        "batch_pause": batch_pause,
    }


async def slow_download(host: str, port: int, index: int, ready: asyncio.Event) -> dict:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    raw_socket = writer.get_extra_info("socket")
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    writer.write(
        f"GET /big.bin?slow={index} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
    if not header.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")):
        raise RuntimeError("slow request failed")
    ready.set()
    await asyncio.sleep(6)
    outcome = "closed"
    received = 0
    try:
        while received < 131072:
            chunk = await asyncio.wait_for(reader.read(16384), 2)
            if not chunk:
                outcome = "eof"
                break
            received += len(chunk)
        else:
            outcome = "read-after-stall"
    except (ConnectionResetError, BrokenPipeError):
        outcome = "reset"
    except asyncio.TimeoutError:
        outcome = "timeout"
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return {"outcome": outcome, "received_after_stall": received}


async def backpressure_client(
    host: str,
    port: int,
    slow_count: int,
    fast_count: int,
    concurrency: int,
    connect_retries: int,
) -> dict:
    ready = [asyncio.Event() for _ in range(slow_count)]
    slow_tasks = [
        asyncio.create_task(slow_download(host, port, index, ready[index]))
        for index in range(slow_count)
    ]
    await asyncio.wait_for(asyncio.gather(*(event.wait() for event in ready)), 20)
    fast = await churn_client(host, port, fast_count, concurrency, connect_retries)
    slow_results = await asyncio.gather(*slow_tasks, return_exceptions=True)
    slow: list[dict] = []
    for result in slow_results:
        if isinstance(result, BaseException):
            slow.append({"outcome": "error", "error": f"{type(result).__name__}:{result}"})
        else:
            slow.append(result)
    return {"fast": fast, "slow": slow}


def udp_client(host: str, port: int, samples: int) -> dict:
    latencies: list[float] = []
    failures = 0
    peer = None
    for index in range(samples):
        payload = f"runtime-memory-{index}".encode()
        sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        started = time.monotonic()
        try:
            sock.sendto(payload, (host, port))
            reply, observed_peer = sock.recvfrom(4096)
            if reply != payload:
                raise RuntimeError("UDP payload mismatch")
            peer = [observed_peer[0], observed_peer[1]]
            latencies.append((time.monotonic() - started) * 1000)
        except Exception:
            failures += 1
        finally:
            sock.close()
    return {
        "samples": samples,
        "failures": failures,
        "loss": failures / samples,
        "p50_ms": percentile(latencies, 0.50),
        "p95_ms": percentile(latencies, 0.95),
        "p99_ms": percentile(latencies, 0.99),
        "peer": peer,
    }


async def download_client(
    host: str, port: int, path: str, delay_ms: float, ready_file: str | None
) -> dict:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    writer.write(
        f"GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
    if not header.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")):
        raise RuntimeError("download request failed")
    content_length = None
    for line in header.decode("latin1").splitlines()[1:]:
        key, separator, value = line.partition(":")
        if separator and key.lower() == "content-length":
            content_length = int(value.strip())
    if ready_file:
        Path(ready_file).touch()
    digest = hashlib.sha256()
    received = 0
    started = time.monotonic()
    while True:
        chunk = await asyncio.wait_for(reader.read(65536), 30)
        if not chunk:
            break
        digest.update(chunk)
        received += len(chunk)
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)
    elapsed = time.monotonic() - started
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    if content_length is not None and received != content_length:
        raise RuntimeError(f"download truncated: {received} != {content_length}")
    return {
        "sha256": digest.hexdigest(),
        "bytes": received,
        "content_length": content_length,
        "elapsed_s": elapsed,
    }


def client_main(args: argparse.Namespace) -> int:
    if args.connect_retries < 0:
        raise ValueError("connect retries must be nonnegative")
    if args.mode != "churn" and args.port is None:
        raise ValueError(f"{args.mode} requires --port")
    if args.mode == "churn" and args.ports is not None and args.port is not None:
        raise ValueError("churn accepts either --port or --ports, not both")
    if args.mode == "churn":
        ports = args.ports or ((args.port,) if args.port is not None else ())
        value = asyncio.run(
            churn_client(
                args.target,
                ports,
                args.count,
                args.concurrency,
                args.connect_retries,
                args.batch_size,
                args.batch_pause,
            )
        )
    elif args.mode == "backpressure":
        value = asyncio.run(
            backpressure_client(
                args.target,
                args.port,
                args.slow,
                args.count,
                args.concurrency,
                args.connect_retries,
            )
        )
    elif args.mode == "udp":
        value = udp_client(args.target, args.port, args.samples)
    elif args.mode == "download":
        value = asyncio.run(
            download_client(args.target, args.port, args.path, args.delay_ms, args.ready_file)
        )
    else:
        raise AssertionError(args.mode)
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


def client_command(args: argparse.Namespace, *arguments: str) -> list[str]:
    return [
        args.ip_binary,
        "netns",
        "exec",
        args.netns,
        sys.executable,
        os.path.realpath(__file__),
        "client",
        *arguments,
    ]


def parse_client_output(returncode: int, stdout: str, stderr: str) -> dict:
    if returncode != 0:
        raise RuntimeError(f"client workload failed ({returncode}): {stderr[-1000:]}")
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("client workload emitted invalid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("client workload did not emit an object")
    return value


def run_client(args: argparse.Namespace, arguments: list[str], timeout: float) -> dict:
    completed = subprocess.run(
        client_command(args, *arguments), capture_output=True, text=True, timeout=timeout
    )
    return parse_client_output(completed.returncode, completed.stdout, completed.stderr)


def run_with_active_samples(
    command: list[str], timeout: float, engine_pid: int, controller: str
) -> tuple[int, str, str, dict]:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + timeout
    peak_metrics = None
    max_connections = 0
    samples = 0
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                stdout, stderr = process.communicate()
                raise TimeoutError(f"active workload timed out: {stdout[-500:]} {stderr[-500:]}")
            metrics = {
                **process_metrics(engine_pid),
                "sample_monotonic": time.monotonic(),
            }
            connections = connection_count(controller)
            samples += 1
            max_connections = max(max_connections, connections)
            if peak_metrics is None or (
                metrics["rss_kib"], metrics["pss_kib"]
            ) > (peak_metrics["rss_kib"], peak_metrics["pss_kib"]):
                peak_metrics = metrics
            if process.poll() is None:
                time.sleep(0.1)
        stdout, stderr = process.communicate()
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.communicate()
        raise
    if peak_metrics is None:
        raise RuntimeError("active workload ended before the first process sample")
    return process.returncode, stdout, stderr, {
        "metrics": peak_metrics,
        "connections": max_connections,
        "samples": samples,
    }


def run_client_with_active_samples(
    args: argparse.Namespace, arguments: list[str], timeout: float
) -> tuple[dict, dict]:
    returncode, stdout, stderr, active = run_with_active_samples(
        client_command(args, *arguments), timeout, args.pid, args.controller
    )
    return parse_client_output(returncode, stdout, stderr), active


def wait_reload_completion(log_path: Path, pid: int, offset: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    cursor = offset
    observed = ""
    request_id = None
    legacy_received = False
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            raise RuntimeError("engine exited during reload")
        size = log_path.stat().st_size
        if size < cursor:
            raise RuntimeError("engine log was truncated during reload")
        if size != cursor:
            with log_path.open("r", encoding="utf-8", errors="replace") as source:
                source.seek(cursor)
                observed += source.read()
                cursor = source.tell()
        if request_id is None:
            matched = re.search(r"SIGHUP reload request ([0-9]+) received", observed)
            if matched:
                request_id = matched.group(1)
        legacy_received = legacy_received or "Received SIGHUP, reloading configuration" in observed
        if request_id is not None:
            if f"SIGHUP reload request {request_id} applied" in observed:
                return
            if f"SIGHUP reload request {request_id} rejected" in observed:
                raise RuntimeError(f"engine rejected reload: {observed[-1000:]}")
        elif legacy_received:
            if "Configuration applied" in observed:
                return
            if any(
                marker in observed
                for marker in (
                    "Reloaded config is invalid",
                    "Failed to reload config",
                    "Failed to send reload command",
                    "reload rejected",
                )
            ):
                raise RuntimeError(f"engine rejected reload: {observed[-1000:]}")
        time.sleep(0.1)
    raise TimeoutError(f"engine did not acknowledge completed reload: {observed[-1000:]}")


def wait_connections_zero(controller: str, timeout: float = 150.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if connection_count(controller) == 0:
            return
        time.sleep(0.25)
    raise RuntimeError(f"connections did not drain: {connection_count(controller)}")


def iperf_action(args: argparse.Namespace, port: int) -> tuple[list[float], float, dict]:
    rates: list[float] = []
    active_runs = []
    for _ in range(args.iperf_runs):
        returncode, stdout, stderr, active = run_with_active_samples(
            [
                args.ip_binary,
                "netns",
                "exec",
                args.netns,
                args.iperf_binary,
                "-c",
                args.target,
                "-p",
                str(port),
                "-t",
                str(args.iperf_seconds),
                "-R",
                "-J",
            ],
            args.iperf_seconds + 15,
            args.pid,
            args.controller,
        )
        if returncode != 0:
            raise RuntimeError(f"iperf failed: {stderr[-500:]}")
        value = json.loads(stdout)
        rate = value["end"]["sum_received"]["bits_per_second"] / 1_000_000
        if not math.isfinite(rate) or rate <= 0:
            raise RuntimeError("iperf reported no throughput")
        rates.append(rate)
        active_runs.append(active)
    peak = max(
        active_runs,
        key=lambda sample: (
            sample["metrics"]["rss_kib"],
            sample["metrics"]["pss_kib"],
        ),
    )
    active = {
        "metrics": peak["metrics"],
        "connections": max(sample["connections"] for sample in active_runs),
        "samples": sum(sample["samples"] for sample in active_runs),
    }
    return rates, statistics.median(rates), active


def base_result() -> dict:
    return {
        "throughput_mbps": 0.0,
        "ops_per_s": 0.0,
        "p50_ms": 0.0,
        "p95_ms": 0.0,
        "p99_ms": 0.0,
        "samples": 0,
        "failures": 0,
        "loss": 0.0,
    }


def validate_row(row: dict) -> None:
    if row.get("schema_version") != 2:
        raise ValueError("schema_version must be 2")
    if row.get("record") != "runtime_memory":
        raise ValueError("record must be runtime_memory")
    if row.get("arm") not in {"baseline", "candidate"}:
        raise ValueError("arm must be baseline or candidate")
    if row.get("scenario") not in {
        "cold",
        "direct_control",
        "reload",
        "throughput",
        "protocol_smoke",
        "churn",
        "backpressure",
        "settled",
    }:
        raise ValueError("unknown runtime-memory scenario")
    for key in COMMON_STRING_FIELDS:
        if not isinstance(row.get(key), str) or not row[key]:
            raise ValueError(f"{key} must be a non-empty string")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", row["source_commit"]):
        raise ValueError("source_commit must be a lowercase Git object ID")
    for key in ("workload_sha256", "driver_sha256", "binary_sha256", "config_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", row[key]):
            raise ValueError(f"{key} must be lowercase SHA-256")
    for key in (
        "run",
        "binary_size_bytes",
        "binary_inode",
        "process_exe_inode",
        "pid",
        "pid_start_time_ticks",
        "config_inode",
        "worker_threads",
        "direct_control_port",
        "churn_count",
        "churn_concurrency",
        "churn_batch_size",
    ):
        if isinstance(row.get(key), bool) or not isinstance(row.get(key), int) or row[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    for key in (
        "binary_device",
        "process_exe_device",
        "config_device",
        "mi_collect_secs",
        "churn_retries",
    ):
        if isinstance(row.get(key), bool) or not isinstance(row.get(key), int) or row[key] < 0:
            raise ValueError(f"{key} must be a non-negative integer")
    if row.get("turbo_disabled") not in {None, 0, 1}:
        raise ValueError("turbo_disabled must be null, 0, or 1")
    for key in REQUIRED_NUMERIC + (
        "elapsed_seconds",
        "minor_faults_delta",
        "major_faults_delta",
        "direct_control_min_mbps",
        "churn_batch_pause",
    ):
        require_nonnegative_number(row.get(key), key)
    if row["direct_control_min_mbps"] <= 0:
        raise ValueError("direct_control_min_mbps must be positive")
    churn_ports = row.get("churn_ports")
    if (
        not isinstance(churn_ports, list)
        or not churn_ports
        or len(set(churn_ports)) != len(churn_ports)
        or any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in churn_ports
        )
    ):
        raise ValueError("churn_ports must be unique ports in 1..65535")
    for key in ("samples", "failures", "connections_before", "connections_after"):
        if isinstance(row[key], bool) or not isinstance(row[key], int):
            raise ValueError(f"{key} must be an integer")
    if not row["p50_ms"] <= row["p95_ms"] <= row["p99_ms"]:
        raise ValueError("latency percentiles are not ordered")
    if not 0 <= row["loss"] <= 1:
        raise ValueError("loss must be in 0..1")
    if not isinstance(row.get("udp_stats_before"), dict) or not isinstance(
        row.get("udp_stats_after"), dict
    ):
        raise ValueError("UDP stats must be objects")
    validate_process_metrics(row.get("process_before"), "process_before")
    validate_process_metrics(row.get("process_after"), "process_after")

    scenario = row["scenario"]
    if scenario in {"cold", "settled"}:
        curve = row.get("curve")
        if not isinstance(curve, list) or len(curve) != row["samples"] or not curve:
            raise ValueError(f"{scenario} curve must match samples")
        for index, sample in enumerate(curve, start=1):
            if not isinstance(sample, dict) or sample.get("second") != index:
                raise ValueError(f"{scenario} curve seconds must be contiguous")
            validate_process_metrics(sample, f"{scenario}.curve[{index - 1}]")
    elif scenario == "reload":
        if not re.fullmatch(r"[0-9a-f]{64}", str(row.get("long_stream_sha256", ""))):
            raise ValueError("reload long_stream_sha256 is invalid")
        if not isinstance(row.get("long_stream_bytes"), int) or row["long_stream_bytes"] <= 0:
            raise ValueError("reload long_stream_bytes must be positive")
        if not isinstance(row.get("udp_results"), list) or not row["udp_results"]:
            raise ValueError("reload udp_results must be a non-empty list")
    elif scenario == "protocol_smoke":
        results = row.get("protocol_results")
        if not isinstance(results, list) or len(results) != 12:
            raise ValueError("protocol_smoke must contain 12 TCP/UDP results")
        for index, result in enumerate(results):
            if not isinstance(result, dict) or result.get("network") not in {"tcp", "udp"}:
                raise ValueError(f"protocol_results[{index}] has invalid network")
            if not isinstance(result.get("port"), int) or result["port"] <= 0:
                raise ValueError(f"protocol_results[{index}] has invalid port")
            if not isinstance(result.get("samples"), int) or result["samples"] <= 0:
                raise ValueError(f"protocol_results[{index}] has invalid samples")
            if result.get("failures") != 0:
                raise ValueError(f"protocol_results[{index}] has failures")
    else:
        validate_process_metrics(row.get("active_process_metrics"), "active_process_metrics")
        for key in ("active_connections", "active_samples", "attempts", "retries"):
            if isinstance(row.get(key), bool) or not isinstance(row.get(key), int) or row[key] < 0:
                raise ValueError(f"{key} must be a non-negative integer")
        if scenario in {"throughput", "direct_control"}:
            rates = row.get("throughput_runs_mbps")
            if not isinstance(rates, list) or not rates:
                raise ValueError("throughput_runs_mbps must be a non-empty list")
            for index, rate in enumerate(rates):
                require_nonnegative_number(rate, f"throughput_runs_mbps[{index}]")
        elif scenario == "backpressure":
            if not isinstance(row.get("slow_outcomes"), list) or not row["slow_outcomes"]:
                raise ValueError("backpressure slow_outcomes must be non-empty")


def run_main(args: argparse.Namespace) -> int:
    binary = Path(args.binary).resolve(strict=True)
    config = Path(args.config).resolve(strict=True)
    engine_log = Path(args.engine_log).resolve(strict=True)
    expected_binary_identity = (
        args.expected_binary_device,
        args.expected_binary_inode,
    )
    if args.expected_binary_size <= 0:
        raise ValueError("expected binary size must be positive")
    if not 1 <= args.direct_control_port <= 65535:
        raise ValueError("direct control port must be in 1..65535")
    if not math.isfinite(args.direct_control_min_mbps) or args.direct_control_min_mbps <= 0:
        raise ValueError("direct control minimum must be positive")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_binary_sha256):
        raise ValueError("expected binary SHA-256 is invalid")
    binary_hash = args.expected_binary_sha256
    config_hash = sha256_file(config)
    config_identity = executable_identity(config)

    def verify_config_snapshot() -> None:
        if executable_identity(config) != config_identity or sha256_file(config) != config_hash:
            raise RuntimeError("immutable config snapshot changed during benchmark")

    verify_config_snapshot()
    initial = process_metrics(args.pid)
    start_time = initial["start_time_ticks"]
    verify_pinned_binary(
        args.pid,
        start_time,
        binary,
        expected_binary_identity,
        args.expected_binary_size,
        binary_hash,
    )
    workload_path = Path(__file__).resolve(strict=True)
    driver_path = workload_path.with_name("runtime-memory.sh").resolve(strict=True)
    common = {
        "schema_version": 2,
        "record": "runtime_memory",
        "arm": args.arm,
        "run": args.run,
        "source_commit": args.source_commit,
        "workload_path": str(workload_path),
        "workload_sha256": sha256_file(workload_path),
        "driver_path": str(driver_path),
        "driver_sha256": sha256_file(driver_path),
        "binary_path": str(binary),
        "binary_sha256": binary_hash,
        "binary_size_bytes": args.expected_binary_size,
        "binary_device": expected_binary_identity[0],
        "binary_inode": expected_binary_identity[1],
        "process_exe_device": expected_binary_identity[0],
        "process_exe_inode": expected_binary_identity[1],
        "pid": args.pid,
        "pid_start_time_ticks": start_time,
        "config_path": str(config),
        "config_sha256": config_hash,
        "config_device": config_identity[0],
        "config_inode": config_identity[1],
        "engine_log_path": str(engine_log),
        "rust_log": "info",
        "kernel": os.uname().release,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "worker_threads": args.worker_threads,
        "mi_collect_secs": args.collect_secs,
        "direct_control_port": args.direct_control_port,
        "direct_control_min_mbps": args.direct_control_min_mbps,
        "churn_ports": list(args.churn_ports),
        "churn_count": args.churn_count,
        "churn_concurrency": args.churn_concurrency,
        "churn_batch_size": args.churn_batch_size,
        "churn_batch_pause": args.churn_batch_pause,
        "churn_retries": args.churn_retries,
        "target": args.target,
        "netns": args.netns,
        "thp_enabled": read_optional_text("/sys/kernel/mm/transparent_hugepage/enabled"),
        "cpu_governor": read_optional_text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "turbo_disabled": read_optional_int("/sys/devices/system/cpu/intel_pstate/no_turbo"),
    }

    def emit_scenario(name: str, action) -> None:
        verify_pinned_binary(
            args.pid,
            start_time,
            binary,
            expected_binary_identity,
            args.expected_binary_size,
            binary_hash,
        )
        verify_config_snapshot()
        before = process_metrics(args.pid)
        connections_before = connection_count(args.controller)
        udp_before = udp_stats(args.controller)
        started = time.monotonic()
        result = {**base_result(), **action()}
        elapsed = time.monotonic() - started
        verify_pinned_binary(
            args.pid,
            start_time,
            binary,
            expected_binary_identity,
            args.expected_binary_size,
            binary_hash,
        )
        verify_config_snapshot()
        after = process_metrics(args.pid)
        connections_after = connection_count(args.controller)
        udp_after = udp_stats(args.controller)
        row = {
            **common,
            "scenario": name,
            "elapsed_seconds": elapsed,
            "rss_kib": after["rss_kib"],
            "peak_rss_kib": after["peak_rss_kib"],
            "pss_kib": after["pss_kib"],
            "private_dirty_kib": after["private_dirty_kib"],
            "minor_faults": after["minor_faults"],
            "major_faults": after["major_faults"],
            "minor_faults_delta": after["minor_faults"] - before["minor_faults"],
            "major_faults_delta": after["major_faults"] - before["major_faults"],
            "cpu_cores": (after["cpu_ticks"] - before["cpu_ticks"])
            / os.sysconf("SC_CLK_TCK")
            / elapsed
            if elapsed
            else 0.0,
            "connections_before": connections_before,
            "connections_after": connections_after,
            "udp_stats_before": udp_before,
            "udp_stats_after": udp_after,
            "process_before": before,
            "process_after": after,
            **result,
        }
        validate_row(row)
        print(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)

    def cold() -> dict:
        curve = []
        for second in range(args.cold_seconds):
            time.sleep(1)
            curve.append({"second": second + 1, **process_metrics(args.pid)})
        return {"samples": len(curve), "curve": curve}

    def direct_control() -> dict:
        wait_connections_zero(args.controller)
        rates, median_rate, active = iperf_action(args, args.direct_control_port)
        if median_rate < args.direct_control_min_mbps:
            raise RuntimeError(
                f"direct control throughput {median_rate:.1f} Mbps is below "
                f"{args.direct_control_min_mbps:.1f} Mbps"
            )
        wait_connections_zero(args.controller)
        return {
            "throughput_mbps": median_rate,
            "samples": len(rates),
            "failures": 0,
            "loss": 0.0,
            "attempts": len(rates),
            "retries": 0,
            "throughput_runs_mbps": rates,
            "active_process_metrics": active["metrics"],
            "active_connections": active["connections"],
            "active_samples": active["samples"],
        }

    def throughput() -> dict:
        wait_connections_zero(args.controller)
        openings = run_client(
            args,
            [
                "--mode",
                "churn",
                "--target",
                args.target,
                "--port",
                str(args.http_port),
                "--count",
                str(args.open_samples),
                "--concurrency",
                "1",
                "--connect-retries",
                "1",
            ],
            args.open_samples * 25,
        )
        if openings["failures"]:
            raise RuntimeError(f"open latency failures: {openings['failure_examples']}")
        rates, median_rate, active = iperf_action(args, args.iperf_port)
        wait_connections_zero(args.controller)
        return {
            "throughput_mbps": median_rate,
            "ops_per_s": openings["ops_per_s"],
            "p50_ms": openings["p50_ms"],
            "p95_ms": openings["p95_ms"],
            "p99_ms": openings["p99_ms"],
            "samples": openings["successes"],
            "failures": 0,
            "loss": 0.0,
            "attempts": openings["attempts"],
            "retries": openings["retries"],
            "throughput_runs_mbps": rates,
            "active_process_metrics": active["metrics"],
            "active_connections": active["connections"],
            "active_samples": active["samples"],
        }

    def churn() -> dict:
        wait_connections_zero(args.controller)
        result, active = run_client_with_active_samples(
            args,
            [
                "--mode",
                "churn",
                "--target",
                args.target,
                "--ports",
                ",".join(str(port) for port in args.churn_ports),
                "--count",
                str(args.churn_count),
                "--concurrency",
                str(args.churn_concurrency),
                "--connect-retries",
                str(args.churn_retries),
                "--batch-size",
                str(args.churn_batch_size),
                "--batch-pause",
                str(args.churn_batch_pause),
            ],
            args.workload_timeout,
        )
        if result["failures"]:
            raise RuntimeError(f"churn failures: {result['failure_examples']}")
        wait_connections_zero(args.controller)
        return {
            "throughput_mbps": result["throughput_mbps"],
            "ops_per_s": result["ops_per_s"],
            "p50_ms": result["p50_ms"],
            "p95_ms": result["p95_ms"],
            "p99_ms": result["p99_ms"],
            "samples": result["successes"],
            "failures": result["failures"],
            "loss": result["failures"] / result["ops"],
            "failure_examples": result["failure_examples"],
            "attempts": result["attempts"],
            "retries": result["retries"],
            "batches": result["batches"],
            "active_process_metrics": active["metrics"],
            "active_connections": active["connections"],
            "active_samples": active["samples"],
        }

    def backpressure() -> dict:
        wait_connections_zero(args.controller)
        result, active = run_client_with_active_samples(
            args,
            [
                "--mode",
                "backpressure",
                "--target",
                args.target,
                "--port",
                str(args.backpressure_port),
                "--count",
                str(args.fast_count),
                "--concurrency",
                str(args.fast_concurrency),
                "--slow",
                str(args.slow_count),
                "--connect-retries",
                "1",
            ],
            args.workload_timeout,
        )
        fast = result["fast"]
        bad_slow = [
            item
            for item in result["slow"]
            if item.get("outcome") in {"error", "timeout", "closed"}
        ]
        if bad_slow or fast["failures"]:
            raise RuntimeError(
                f"backpressure failed: fast={fast['failure_examples']} slow={bad_slow}"
            )
        wait_connections_zero(args.controller)
        return {
            "throughput_mbps": fast["throughput_mbps"],
            "ops_per_s": fast["ops_per_s"],
            "p50_ms": fast["p50_ms"],
            "p95_ms": fast["p95_ms"],
            "p99_ms": fast["p99_ms"],
            "samples": fast["successes"],
            "failures": fast["failures"],
            "loss": fast["failures"] / fast["ops"],
            "slow_outcomes": result["slow"],
            "fast_failure_examples": fast["failure_examples"],
            "attempts": fast["attempts"],
            "retries": fast["retries"],
            "active_process_metrics": active["metrics"],
            "active_connections": active["connections"],
            "active_samples": active["samples"],
        }

    def protocol_smoke() -> dict:
        wait_connections_zero(args.controller)
        results = []
        samples = 0
        for port in PROTOCOL_TCP_PORTS:
            tcp = run_client(
                args,
                [
                    "--mode",
                    "churn",
                    "--target",
                    args.target,
                    "--port",
                    str(port),
                    "--count",
                    "3",
                    "--concurrency",
                    "1",
                    "--connect-retries",
                    "1",
                ],
                60,
            )
            if tcp["failures"]:
                raise RuntimeError(
                    f"TCP protocol smoke failed on port {port}: {tcp['failure_examples']}"
                )
            samples += tcp["successes"]
            results.append(
                {
                    "network": "tcp",
                    "port": port,
                    "samples": tcp["successes"],
                    "failures": 0,
                    "p50_ms": tcp["p50_ms"],
                    "p95_ms": tcp["p95_ms"],
                    "p99_ms": tcp["p99_ms"],
                    "attempts": tcp["attempts"],
                    "retries": tcp["retries"],
                }
            )

        for port in PROTOCOL_UDP_PORTS:
            udp = run_client(
                args,
                [
                    "--mode",
                    "udp",
                    "--target",
                    args.target,
                    "--port",
                    str(port),
                    "--samples",
                    "3",
                ],
                60,
            )
            peer = udp.get("peer")
            valid_peer = (
                isinstance(peer, list)
                and len(peer) == 2
                and ipaddress.ip_address(peer[0]) == ipaddress.ip_address(args.target)
                and peer[1] == port
            )
            if udp["failures"] or not valid_peer:
                raise RuntimeError(f"UDP protocol smoke failed on port {port}: {udp}")
            samples += udp["samples"]
            results.append(
                {
                    "network": "udp",
                    "port": port,
                    "samples": udp["samples"],
                    "failures": 0,
                    "loss": udp["loss"],
                    "p50_ms": udp["p50_ms"],
                    "p95_ms": udp["p95_ms"],
                    "p99_ms": udp["p99_ms"],
                    "peer": peer,
                }
            )

        wait_connections_zero(args.controller)
        return {
            "samples": samples,
            "failures": 0,
            "loss": 0.0,
            "protocol_results": results,
        }

    def reload_continuity() -> dict:
        control = run_client(
            args,
            [
                "--mode",
                "download",
                "--target",
                args.target,
                "--port",
                str(args.reload_port),
                "--path",
                args.reload_path,
            ],
            args.workload_timeout,
        )
        ready_file = Path(args.run_dir) / f"reload-download-{args.run}-{args.arm}.ready"
        ready_file.unlink(missing_ok=True)
        command = client_command(
            args,
            "--mode",
            "download",
            "--target",
            args.target,
            "--port",
            str(args.reload_port),
            "--path",
            args.reload_path,
            "--delay-ms",
            str(args.reload_delay_ms),
            "--ready-file",
            str(ready_file),
        )
        download = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            deadline = time.monotonic() + 20
            while not ready_file.exists():
                if download.poll() is not None:
                    stdout, stderr = download.communicate()
                    raise RuntimeError(
                        "reload download exited before ready "
                        f"rc={download.returncode}: {stdout} {stderr}"
                    )
                if time.monotonic() >= deadline:
                    raise TimeoutError("reload download did not become ready")
                time.sleep(0.05)
            if args.reloads < 1:
                raise ValueError("reloads must be positive")
            latencies: list[float] = []
            udp_results = []
            reload_started = time.monotonic()

            def probe_reload(check_udp: bool) -> None:
                started = time.monotonic()
                verify_config_snapshot()
                log_offset = engine_log.stat().st_size
                os.kill(args.pid, signal.SIGHUP)
                wait_reload_completion(engine_log, args.pid, log_offset)
                verify_config_snapshot()
                result = run_client(
                    args,
                    [
                        "--mode",
                        "churn",
                        "--target",
                        args.target,
                        "--port",
                        str(args.reload_http_port),
                        "--count",
                        "1",
                        "--concurrency",
                        "1",
                    ],
                    30,
                )
                if result["failures"]:
                    raise RuntimeError("new TCP flow failed after reload")
                latencies.append((time.monotonic() - started) * 1000)
                if check_udp:
                    udp = run_client(
                        args,
                        [
                            "--mode",
                            "udp",
                            "--target",
                            args.target,
                            "--port",
                            str(args.udp_port),
                            "--samples",
                            "1",
                        ],
                        30,
                    )
                    peer = udp.get("peer")
                    valid_peer = (
                        isinstance(peer, list)
                        and len(peer) == 2
                        and ipaddress.ip_address(peer[0]) == ipaddress.ip_address(args.target)
                        and peer[1] == args.udp_port
                    )
                    if udp["failures"] or not valid_peer:
                        raise RuntimeError(f"UDP continuity failed: {udp}")
                    udp_results.append(udp)
                time.sleep(args.reload_interval)

            if download.poll() is not None:
                stdout, stderr = download.communicate()
                raise RuntimeError(
                    f"long download ended before reload rc={download.returncode}: {stdout} {stderr}"
                )
            probe_reload(True)
            try:
                stdout, stderr = download.communicate(timeout=args.workload_timeout)
            except subprocess.TimeoutExpired as error:
                raise TimeoutError("reload download timed out") from error
            if download.returncode != 0:
                raise RuntimeError(f"reload download failed: {stderr[-1000:]}")
            observed = json.loads(stdout)
            if observed["sha256"] != control["sha256"] or observed["bytes"] != control["bytes"]:
                raise RuntimeError("reload changed or truncated the long stream")
            for _ in range(1, args.reloads):
                probe_reload(False)
            wait_connections_zero(args.controller)
            elapsed = observed["elapsed_s"]
            reload_elapsed = time.monotonic() - reload_started
            return {
                "throughput_mbps": observed["bytes"] * 8 / elapsed / 1_000_000
                if elapsed
                else 0.0,
                "ops_per_s": args.reloads / reload_elapsed if reload_elapsed else 0.0,
                "p50_ms": percentile(latencies, 0.50),
                "p95_ms": percentile(latencies, 0.95),
                "p99_ms": percentile(latencies, 0.99),
                "samples": args.reloads,
                "failures": 0,
                "loss": 0.0,
                "long_stream_sha256": observed["sha256"],
                "long_stream_bytes": observed["bytes"],
                "udp_results": udp_results,
            }
        finally:
            ready_file.unlink(missing_ok=True)
            if download.poll() is None:
                download.kill()
                download.communicate()

    def settled() -> dict:
        wait_connections_zero(args.controller)
        curve = []
        for second in range(args.settle_seconds):
            time.sleep(1)
            verify_process_identity(args.pid, start_time, expected_binary_identity)
            curve.append({"second": second + 1, **process_metrics(args.pid)})
        wait_connections_zero(args.controller)
        return {"samples": len(curve), "curve": curve}

    emit_scenario("cold", cold)
    emit_scenario("direct_control", direct_control)
    emit_scenario("throughput", throughput)
    emit_scenario("churn", churn)
    emit_scenario("backpressure", backpressure)
    emit_scenario("reload", reload_continuity)
    emit_scenario("protocol_smoke", protocol_smoke)
    emit_scenario("settled", settled)
    return 0


def fixture_main(args: argparse.Namespace) -> int:
    with Path(args.fixture).open(encoding="utf-8") as source:
        fixture = json.load(source)
    rows = fixture["rows"][args.arm]
    if not isinstance(rows, list) or not rows:
        raise ValueError("fixture arm must contain rows")
    for template in rows:
        row = {**template, "arm": args.arm, "run": args.run}
        validate_row(row)
        print(json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="honk runtime-memory workload helper")
    sub = root.add_subparsers(dest="command", required=True)

    client = sub.add_parser("client")
    client.add_argument("--mode", choices=("churn", "backpressure", "udp", "download"), required=True)
    client.add_argument("--target", required=True)
    client.add_argument("--port", type=int)
    client.add_argument("--ports", type=parse_ports)
    client.add_argument("--count", type=int, default=0)
    client.add_argument("--concurrency", type=int, default=1)
    client.add_argument("--slow", type=int, default=0)
    client.add_argument("--connect-retries", type=int, default=0)
    client.add_argument("--batch-size", type=int)
    client.add_argument("--batch-pause", type=float, default=0)
    client.add_argument("--samples", type=int, default=1)
    client.add_argument("--path", default="/")
    client.add_argument("--delay-ms", type=float, default=0)
    client.add_argument("--ready-file")

    fixture = sub.add_parser("fixture")
    fixture.add_argument("--fixture", required=True)
    fixture.add_argument("--arm", choices=("baseline", "candidate"), required=True)
    fixture.add_argument("--run", type=int, required=True)

    run = sub.add_parser("run")
    run.add_argument("--pid", type=int, required=True)
    run.add_argument("--binary", required=True)
    run.add_argument("--source-commit", required=True)
    run.add_argument("--expected-binary-device", type=int, required=True)
    run.add_argument("--expected-binary-inode", type=int, required=True)
    run.add_argument("--expected-binary-size", type=int, required=True)
    run.add_argument("--expected-binary-sha256", required=True)
    run.add_argument("--config", required=True)
    run.add_argument("--engine-log", required=True)
    run.add_argument("--arm", choices=("baseline", "candidate"), required=True)
    run.add_argument("--run", type=int, required=True)
    run.add_argument("--run-dir", required=True)
    run.add_argument("--target", type=parse_target, required=True)
    run.add_argument("--netns", default="lab")
    run.add_argument("--controller", default="http://127.0.0.1:9090")
    run.add_argument("--ip-binary", default="ip")
    run.add_argument("--iperf-binary", default="iperf3")
    run.add_argument("--direct-control-port", type=int, default=5300)
    run.add_argument("--direct-control-min-mbps", type=float, default=8930)
    run.add_argument("--worker-threads", type=int, default=16)
    run.add_argument("--collect-secs", type=int, default=60)
    run.add_argument("--cold-seconds", type=int, default=130)
    run.add_argument("--settle-seconds", type=int, default=130)
    run.add_argument("--http-port", type=int, default=8005)
    run.add_argument("--open-samples", type=int, default=15)
    run.add_argument("--iperf-port", type=int, default=5205)
    run.add_argument("--iperf-runs", type=int, default=3)
    run.add_argument("--iperf-seconds", type=int, default=8)
    run.add_argument("--churn-ports", type=parse_ports, default=CHURN_PORTS)
    run.add_argument("--churn-count", type=int, default=20000)
    run.add_argument("--churn-concurrency", type=int, default=64)
    run.add_argument("--churn-batch-size", type=int, default=2000)
    run.add_argument("--churn-batch-pause", type=float, default=1)
    run.add_argument("--churn-retries", type=int, default=3)
    run.add_argument("--backpressure-port", type=int, default=18007)
    run.add_argument("--slow-count", type=int, default=8)
    run.add_argument("--fast-count", type=int, default=1000)
    run.add_argument("--fast-concurrency", type=int, default=16)
    run.add_argument("--reload-port", type=int, default=18007)
    run.add_argument("--reload-http-port", type=int, default=8006)
    run.add_argument("--reload-path", default="/big.bin")
    run.add_argument("--reload-delay-ms", type=float, default=2)
    run.add_argument("--reloads", type=int, default=20)
    run.add_argument("--reload-interval", type=float, default=0.75)
    run.add_argument("--udp-port", type=int, default=53536)
    run.add_argument("--workload-timeout", type=float, default=1800)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "client":
        return client_main(args)
    if args.command == "fixture":
        return fixture_main(args)
    if args.command == "run":
        return run_main(args)
    raise AssertionError(args.command)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError, RuntimeError, OSError, json.JSONDecodeError) as error:
        print(f"runtime-memory-workload: {error}", file=sys.stderr)
        raise SystemExit(1)
