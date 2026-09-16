#!/usr/bin/env python3
"""Bounded real-core LAN-netns A/B driver; run as root on the engine host.

Fixtures: /bytes/N returns exactly N 'Z' bytes and X-Bench-Peer; UDP returns
HB1 + inet_aton(observed_sender_ip) + the original datagram. HTTPS intentionally
uses an unverified lab certificate. This measures opens, downloads and small
sequential UDP echoes, NOT full VLESS uplink throughput or Internet performance.
Requires Python 3.12+ (os.setns), iproute2 and nft; no Python dependencies.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import statistics
import struct
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

SCHEMA_VERSION = 1
TARGET = "10.10.10.70"
NAMESPACE = "lab-pr246"
HOST_VETH = "hp246"
PEER_VETH = "veth-pr246"
SUBNET = "192.168.246.0/30"
CLIENT = "192.168.246.2"
GATEWAY = "192.168.246.1"
TABLE = "honk_bench_pr246"
DOWNLOAD_BYTES = 16 * 1024 * 1024
HTTP_OPENS = 15
DOWNLOADS = 3  # Each of HTTP and HTTPS, not three pooled across both.
UDP_SAMPLES = 100  # Per destination, one socket for both destinations.
HTTP_TIMEOUT = 5
DOWNLOAD_TIMEOUT = 30
UDP_TIMEOUT = 1
SETUP_SETTLE_SECONDS = 5
CLIENT_TIMEOUT = HTTP_OPENS * HTTP_TIMEOUT + 2 * DOWNLOADS * DOWNLOAD_TIMEOUT + 2 * UDP_SAMPLES * UDP_TIMEOUT + 30
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
DEFER_SIGNALS = 0
PENDING_SIGNAL = None


def require(condition, message):
    if not condition:
        raise ValueError(message)


def interrupted(signum, _frame):
    global PENDING_SIGNAL
    if DEFER_SIGNALS:
        PENDING_SIGNAL = signum
    else:
        raise KeyboardInterrupt(f"received signal {signum}")


def alarm(_signum, _frame):
    raise TimeoutError("absolute operation deadline exceeded")


@contextmanager
def deadline(seconds):
    previous, interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, min(seconds, previous) if previous else seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if previous:
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, previous - (time.monotonic() - started)), interval)


@contextmanager
def acquisition():
    # Defer termination until the new resource has its cleanup obligation recorded.
    global DEFER_SIGNALS, PENDING_SIGNAL
    DEFER_SIGNALS += 1
    try:
        yield
    finally:
        DEFER_SIGNALS -= 1
        if not DEFER_SIGNALS and PENDING_SIGNAL is not None:
            signum, PENDING_SIGNAL = PENDING_SIGNAL, None
            interrupted(signum, None)


def clean_environment():
    return {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}


def read_bytes(path, limit):
    with deadline(30), open(path, "rb") as source:
        data = source.read(limit + 1)
    require(len(data) <= limit, f"file exceeds {limit} bytes: {path}")
    return data


def sha256_file(path):
    digest = hashlib.sha256()
    total = 0
    with deadline(30), open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            require(total <= 512 * 1024 * 1024, f"file exceeds 512 MiB: {path}")
            digest.update(chunk)
    require(total > 0, f"empty file: {path}")
    return digest.hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)


def check_keys(value, required, optional=()):
    require(isinstance(value, dict), "expected JSON object")
    require(set(required) <= value.keys(), f"missing keys: {sorted(set(required) - value.keys())}")
    require(value.keys() <= set(required) | set(optional), f"unknown keys: {sorted(value.keys() - set(required) - set(optional))}")


def check_ports(case, named=True):
    check_keys(case, ["http_port", "https_port", "udp_ports"] + (["name"] if named else []))
    if named:
        require(isinstance(case["name"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", case["name"]), "invalid case name")
        require(case["name"] != "direct", "direct is a reserved case name")
    require(isinstance(case["udp_ports"], list) and len(case["udp_ports"]) == 2, "udp_ports must contain two ports")
    ports = [case["http_port"], case["https_port"], *case["udp_ports"]]
    require(all(type(port) is int and 1024 <= port <= 65535 for port in ports), "ports must be integers in 1024..65535")
    require(len(set(ports)) == 4, "case ports must be distinct")
    return ports


def verified_arm(arm):
    for path_key, hash_key in (("binary", "sha256"), ("config", "config_sha256")):
        path = Path(arm[path_key])
        require(path.is_absolute() and path.is_file(), f"missing absolute regular {path_key}: {path}")
        require(sha256_file(path) == arm[hash_key], f"{path_key} SHA256 mismatch: {path}")
    require(os.access(arm["binary"], os.X_OK), "binary is not executable")


def load_manifest(path):
    require(hasattr(os, "setns"), "Python 3.12+ with os.setns is required")
    raw = read_bytes(path, 1024 * 1024)
    manifest = strict_json(raw)
    check_keys(manifest, ["arms", "api", "target", "namespace", "host_veth", "peer_veth", "subnet", "client", "gateway", "cases", "direct", "runs"], ["service"])
    for key, expected in (("target", TARGET), ("namespace", NAMESPACE), ("host_veth", HOST_VETH), ("peer_veth", PEER_VETH), ("subnet", SUBNET), ("client", CLIENT), ("gateway", GATEWAY)):
        require(manifest[key] == expected, f"{key} must be {expected}")
    require(type(manifest["runs"]) is int and manifest["runs"] == 3, "runs must be 3 paired runs")
    check_keys(manifest["arms"], ["baseline", "candidate"])
    for arm in manifest["arms"].values():
        check_keys(arm, ["binary", "sha256", "commit", "config", "config_sha256", "profile"])
        require(all(isinstance(value, str) and value for value in arm.values()), "arm fields must be nonempty strings")
        require(re.fullmatch(r"[0-9a-f]{64}", arm["sha256"]) and re.fullmatch(r"[0-9a-f]{64}", arm["config_sha256"]), "SHA256 must be 64 lowercase hex digits")
        require(re.fullmatch(r"[0-9a-f]{7,40}", arm["commit"]), "commit must be 7..40 lowercase hex digits")
        verified_arm(arm)
    check_keys(manifest["api"], ["url", "token"])
    require(isinstance(manifest["api"]["url"], str) and isinstance(manifest["api"]["token"], str), "API URL/token must be strings")
    url = urlsplit(manifest["api"]["url"])
    require(url.scheme == "http" and url.hostname == "127.0.0.1" and url.port is not None and 1 <= url.port <= 65535 and url.path in ("", "/") and not url.query and not url.fragment and not url.username and not url.password, "API must be http://127.0.0.1:PORT without credentials/path/query")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in manifest["api"]["token"]), "invalid API token characters")
    require(isinstance(manifest["cases"], list) and 1 <= len(manifest["cases"]) <= 32, "cases must contain 1..32 cases")
    ports = check_ports(manifest["direct"], named=False)
    names = set()
    for case in manifest["cases"]:
        require(case.get("name") not in names, "duplicate case name")
        ports.extend(check_ports(case))
        names.add(case["name"])
    require(len(ports) == len(set(ports)), "ports must be distinct across all cases/direct controls")
    if "service" in manifest:
        require(manifest["service"] == "/etc/init.d/honk" and os.uname().machine in ("aarch64", "arm64", "armv7l"), "service stop/restore is restricted to ARM /etc/init.d/honk")
        require(Path(manifest["service"]).is_file() and os.access(manifest["service"], os.X_OK), "missing executable service script")
    return manifest, hashlib.sha256(raw).hexdigest()


def proc_stats(pid):
    fields = read_bytes(f"/proc/{pid}/stat", 16384).decode().rsplit(")", 1)[1].split()
    values = {"utime_ticks": int(fields[11]), "stime_ticks": int(fields[12]), "starttime_ticks": int(fields[19]), "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE")}
    require(all(value >= 0 for value in values.values()) and values["starttime_ticks"] > 0, "invalid process counters")
    return values


def stop_owned(process, starttime=None, grace=20):
    if process.poll() is not None:
        return False
    if starttime is not None:
        require(proc_stats(process.pid)["starttime_ticks"] == starttime, "refusing to signal changed process identity")
    require(os.getpgid(process.pid) == process.pid, "refusing to signal unowned process group")
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
        return False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        return True


def command(argv, timeout=10, input_text=None, allowed=(0,)):
    process = None
    try:
        with acquisition():
            process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=clean_environment(), start_new_session=True)
        stdout, stderr = process.communicate(input_text, timeout=timeout)
        require(process.returncode in allowed, f"command failed ({process.returncode}): {argv!r}: {stderr[:2000]}")
        return process.returncode, stdout
    finally:
        if process is not None:
            stop_owned(process, grace=2)


def command_json(argv):
    return strict_json(command(argv)[1])


def api_request(api, path):
    connection = http.client.HTTPConnection("127.0.0.1", urlsplit(api["url"]).port, timeout=2)
    try:
        with deadline(3):
            headers = {"Connection": "close"}
            if api["token"]:
                headers["Authorization"] = "Bearer " + api["token"]
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            data = response.read(4 * 1024 * 1024 + 1)
            require(response.status == 200, f"API {path} status {response.status}")
            require(len(data) <= 4 * 1024 * 1024, "API response too large")
            value = strict_json(data)
            require(isinstance(value, dict) and value, f"invalid API {path} object")
            return value
    finally:
        connection.close()


def api_owned(pid, port):
    with deadline(3):
        inodes = set()
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            try:
                link = os.readlink(fd)
            except FileNotFoundError:
                continue
            if link.startswith("socket:["):
                inodes.add(link[8:-1])
        for filename, addresses in (("tcp", {"00000000", "0100007F"}), ("tcp6", {"0" * 32, "0000000000000000FFFF00000100007F"})):
            rows = read_bytes(f"/proc/{pid}/net/{filename}", 8 * 1024 * 1024).decode().splitlines()[1:]
            for row in rows:
                fields = row.split()
                address, raw_port = fields[1].split(":")
                if fields[3] == "0A" and int(raw_port, 16) == port and address in addresses and fields[9] in inodes:
                    return True
    return False


def stats_snapshot(api):
    value = api_request(api, "/stats")
    require(isinstance(value.get("outbounds"), list) and isinstance(value.get("tcp"), dict) and isinstance(value.get("udp"), dict), "incomplete /stats schema")
    numbers = 0

    def visit(item, path=""):
        nonlocal numbers
        if isinstance(item, dict):
            for key, child in item.items():
                visit(child, path + "/" + key)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, path + f"/{index}")
        elif type(item) in (int, float):
            require(math.isfinite(item) and item >= 0, f"invalid /stats counter at {path}")
            numbers += 1
        elif isinstance(item, str):
            require(path.endswith("/name"), f"nonnumeric /stats counter at {path}")
        else:
            require(item is None or type(item) is bool, f"invalid /stats value at {path}")

    visit(value)
    require(numbers > 0, "/stats has no numeric counters")
    return value  # Preserve native names/gauges; do not invent source keys or deltas.


def json_line(sink, value):
    with deadline(5):
        sink.write(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
        sink.flush()


@lru_cache(maxsize=2)
def expected_digest(length):
    digest = hashlib.sha256()
    block = b"Z" * 65536
    while length:
        size = min(length, len(block))
        digest.update(block[:size])
        length -= size
    return digest.hexdigest()


def http_attempt(spec, kind, index, length, tls):
    port = spec["case"]["https_port" if tls else "http_port"]
    timeout = DOWNLOAD_TIMEOUT if length > 1 else HTTP_TIMEOUT
    # http.client never uses proxy environment variables; redirects are not followed.
    connection = http.client.HTTPSConnection(TARGET, port, timeout=timeout, context=ssl._create_unverified_context()) if tls else http.client.HTTPConnection(TARGET, port, timeout=timeout)
    row = {"kind": kind, "index": index, "port": port, "tls_verified": False if tls else None, "expected_bytes": length, "expected_sha256": expected_digest(length), "bytes": 0, "status": None, "peer": None, "ok": False}
    digest = hashlib.sha256()
    started = time.perf_counter_ns()
    try:
        with deadline(timeout):
            connection.request("GET", f"/bytes/{length}", headers={"Host": TARGET, "Connection": "close", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            row["status"] = response.status
            row["peer"] = response.getheader("X-Bench-Peer")
            while chunk := response.read(min(65536, length + 1 - row["bytes"])):
                row["bytes"] += len(chunk)
                digest.update(chunk)
                require(row["bytes"] <= length, "HTTP body exceeds expected length")
            require(row["status"] == 200, "HTTP status is not 200")
            require(row["bytes"] == length and digest.hexdigest() == row["expected_sha256"], "HTTP body length/hash mismatch")
            require(row["peer"] in spec["expected_peers"], "HTTP peer provenance mismatch")
            row["ok"] = True
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        connection.close()
    row["elapsed_s"] = (time.perf_counter_ns() - started) / 1_000_000_000
    row["sha256"] = digest.hexdigest()
    row["rate_bytes_s"] = row["bytes"] / row["elapsed_s"] if row["ok"] else None
    return row


def client_main(raw_spec):
    spec = strict_json(raw_spec)
    os.setns(spec["netns_fd"], os.CLONE_NEWNET)
    os.close(spec["netns_fd"])
    require(os.stat("/proc/self/ns/net").st_ino == spec["netns_inode"], "client is not in the owned namespace")
    failed = False

    def emit(row):
        nonlocal failed
        failed |= not row["ok"]
        json_line(sys.stdout, row)

    emit(http_attempt(spec, "http_warmup", 0, 1, False))
    for index in range(HTTP_OPENS):
        emit(http_attempt(spec, "http_open", index, 1, False))
    for tls in (False, True):
        for index in range(DOWNLOADS):
            emit(http_attempt(spec, "https_download" if tls else "http_download", index, DOWNLOAD_BYTES, tls))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(UDP_TIMEOUT)
        udp.bind((CLIENT, 0))
        nonce = os.urandom(16)
        for destination_index, port in enumerate(spec["case"]["udp_ports"]):
            for index in range(UDP_SAMPLES):
                sequence = destination_index * UDP_SAMPLES + index
                payload = nonce + struct.pack("!HI", port, sequence) + b"Z" * (1200 - 22)
                row = {"kind": "udp_echo", "index": index, "sequence": sequence, "port": port, "client_port": udp.getsockname()[1], "nonce": nonce.hex(), "payload_bytes": len(payload), "payload_sha256": hashlib.sha256(payload).hexdigest(), "reply_bytes": 0, "mismatches": [], "ok": False}
                started = time.perf_counter_ns()
                try:
                    with deadline(UDP_TIMEOUT):
                        require(udp.sendto(payload, (TARGET, port)) == len(payload), "short UDP send")
                        reply, address = udp.recvfrom(65535)
                        row["reply_bytes"] = len(reply)
                        row["reply_address"] = list(address)
                        row["reply_sha256"] = hashlib.sha256(reply).hexdigest()
                        peer = socket.inet_ntoa(reply[3:7]) if len(reply) >= 7 else None
                        row["peer"] = peer
                        if address != (TARGET, port):
                            row["mismatches"].append("reply_address")
                        if reply[:3] != b"HB1" or len(reply) < 7:
                            row["mismatches"].append("prefix")
                        if peer not in spec["expected_peers"]:
                            row["mismatches"].append("peer_provenance")
                        if reply[7:] != payload:
                            row["mismatches"].append("payload")
                        require(not row["mismatches"], "UDP receive mismatch")
                        row["ok"] = True
                except Exception as exc:
                    row["error"] = f"{type(exc).__name__}: {exc}"
                row["elapsed_s"] = (time.perf_counter_ns() - started) / 1_000_000_000
                emit(row)
        # A queued duplicate after the last response is an error, not a hidden sample.
        udp.settimeout(0.05)
        try:
            with deadline(0.1):
                reply, address = udp.recvfrom(65535)
                emit({"kind": "udp_unexpected", "ok": False, "reply_bytes": len(reply), "reply_address": list(address), "error": "unexpected trailing datagram"})
        except (TimeoutError, socket.timeout):
            pass
    return 1 if failed else 0


def summarize(rows, case):
    expected = {(kind, case["http_port"], index) for kind, count in (("http_warmup", 1), ("http_open", HTTP_OPENS), ("http_download", DOWNLOADS)) for index in range(count)}
    expected |= {("https_download", case["https_port"], index) for index in range(DOWNLOADS)}
    expected |= {("udp_echo", port, index) for port in case["udp_ports"] for index in range(UDP_SAMPLES)}
    seen = set()
    for row in rows:
        if row["kind"] == "udp_unexpected":
            continue
        key = (row["kind"], row["port"], row["index"])
        require(key in expected and key not in seen, "duplicate/unexpected attempt row")
        seen.add(key)
        require(type(row["ok"]) is bool and isinstance(row["elapsed_s"], (int, float)) and math.isfinite(row["elapsed_s"]) and row["elapsed_s"] > 0, "invalid attempt counters")
    require(seen == expected, f"incomplete rows: {len(seen)} of {len(expected)} attempts")
    udp_rows = [row for row in rows if row["kind"] == "udp_echo"]
    require(len({row["client_port"] for row in udp_rows}) == 1 and len({row["nonce"] for row in udp_rows}) == 1 and {row["sequence"] for row in udp_rows} == set(range(2 * UDP_SAMPLES)), "UDP socket/sequence continuity is incomplete")
    summaries = []
    for kind, port in sorted({(row["kind"], row["port"]) for row in rows if "port" in row}):
        attempts = [row for row in rows if row["kind"] == kind and row.get("port") == port]
        failures = sum(not row["ok"] for row in attempts)
        elapsed = sorted(row["elapsed_s"] for row in attempts)
        summaries.append({"kind": kind, "port": port, "attempts": len(attempts), "failures": failures, "receive_mismatches": sum(bool(row.get("mismatches")) for row in attempts), "elapsed_median_s": statistics.median(elapsed) if not failures else None, "elapsed_p95_s": elapsed[math.ceil(0.95 * len(elapsed)) - 1] if not failures else None, "rate_median_bytes_s": statistics.median(row["rate_bytes_s"] for row in attempts) if not failures and kind in ("http_download", "https_download") else None, "attempted_elapsed_s_including_failures": sum(elapsed)})
    return summaries


class Driver:
    def __init__(self, manifest, sink, assets):
        self.manifest, self.sink, self.assets = manifest, sink, assets
        self.sequence = 0
        self.namespace_inode = None
        self.namespace_fd = None
        self.link_index = None
        self.link_attempted = False
        self.table_attempted = False
        self.fw4_rule_attempted = False
        self.fw4_rule_handle = None
        self.forwarding = None
        self.socket_limits = {}
        self.restore_service = False
        self.service_cron = None
        self.engine = None
        self.engine_start = None
        self.engine_stdio = None
        self.owner = "honk-pr246-" + uuid.uuid4().hex
        self.completed_cases = 0
        self.failed_cases = 0

    def emit(self, kind, **value):
        self.sequence += 1
        json_line(self.sink, {"schema_version": SCHEMA_VERSION, "sequence": self.sequence, "record": kind, "time_utc": datetime.now(timezone.utc).isoformat(), **value})
        if kind in ("engine_started", "case_summary", "error", "cleanup", "result"):
            print(kind + ": " + json.dumps(value, sort_keys=True), flush=True)

    def service_running(self):
        return command([self.manifest["service"], "running"], allowed=(0, 1))[0] == 0

    def await_service(self, running):
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if self.service_running() == running:
                return
            time.sleep(0.25)
        raise TimeoutError(f"service failed to reach running={running}")

    def setup(self):
        namespaces = command(["ip", "netns", "list"])[1]
        require(all(line.split()[0] != NAMESPACE for line in namespaces.splitlines() if line.split()), "refusing preexisting client namespace")
        require(not os.path.lexists(f"/var/run/netns/{NAMESPACE}"), "refusing preexisting namespace path")
        links = command_json(["ip", "-j", "link", "show"])
        require(not {HOST_VETH, PEER_VETH} & {link["ifname"] for link in links}, "refusing preexisting veth link")
        tables = command_json(["nft", "-j", "list", "tables"])["nftables"]
        require(not any(item.get("table", {}).get("name") == TABLE for item in tables), "refusing preexisting benchmark nft table")
        route = command_json(["ip", "-j", "route", "get", TARGET])[0]
        self.external_ip = route.get("prefsrc", route.get("src"))
        self.external_link = route["dev"]
        require(self.external_ip is not None and self.external_ip != TARGET and not ipaddress.IPv4Address(self.external_ip).is_loopback, "cannot derive non-peer engine external address")
        require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", self.external_link), "unsafe external interface name")
        self.socket_limits = {
            path: read_bytes(path, 32).decode().strip()
            for path in ("/proc/sys/net/core/rmem_max", "/proc/sys/net/core/wmem_max")
        }
        if "service" in self.manifest:
            with acquisition():
                if self.service_running():
                    cron = Path("/etc/crontabs/root")
                    self.service_cron = read_bytes(cron, 1024 * 1024).decode() if cron.exists() else None
                    self.restore_service = True
                    command([self.manifest["service"], "stop"], timeout=30)
            if self.restore_service:
                self.await_service(False)
            self.emit("service", initially_running=self.restore_service)
        with socket.socket() as probe:
            probe.settimeout(2)
            require(probe.connect_ex(("127.0.0.1", urlsplit(self.manifest["api"]["url"]).port)) != 0, "API port already occupied after service stop")
        self.forwarding = read_bytes("/proc/sys/net/ipv4/ip_forward", 16).decode().strip()
        require(self.forwarding in ("0", "1"), "invalid ip_forward value")
        with acquisition():
            command(["ip", "netns", "add", NAMESPACE])
            self.namespace_fd = os.open(f"/var/run/netns/{NAMESPACE}", os.O_RDONLY | os.O_CLOEXEC)
            self.namespace_inode = os.fstat(self.namespace_fd).st_ino
        with acquisition():
            self.link_attempted = True
            command(["ip", "link", "add", HOST_VETH, "type", "veth", "peer", "name", PEER_VETH])
            self.link_index = command_json(["ip", "-j", "link", "show", "dev", HOST_VETH])[0]["ifindex"]
        command(["ip", "link", "set", PEER_VETH, "netns", NAMESPACE])
        command(["ip", "address", "add", GATEWAY + "/30", "dev", HOST_VETH])
        command(["ip", "link", "set", HOST_VETH, "up"])
        command(["ip", "-n", NAMESPACE, "address", "add", CLIENT + "/30", "dev", PEER_VETH])
        command(["ip", "-n", NAMESPACE, "link", "set", PEER_VETH, "up"])
        command(["ip", "-n", NAMESPACE, "link", "set", "lo", "up"])
        command(["ip", "-n", NAMESPACE, "route", "add", "default", "via", GATEWAY])
        rules = f'create table ip {TABLE} {{ comment "{self.owner}"; }}\nadd chain ip {TABLE} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\nadd rule ip {TABLE} postrouting iifname "{HOST_VETH}" oifname "{self.external_link}" ip saddr {SUBNET} ip daddr {TARGET} masquerade\n'
        with acquisition():
            self.table_attempted = True
            command(["nft", "-f", "-"], input_text=rules)
        if "service" in self.manifest:
            direct = self.manifest["direct"]
            ports = ", ".join(map(str, [direct["http_port"], direct["https_port"], *direct["udp_ports"]]))
            rule = f'insert rule inet fw4 forward iifname "{HOST_VETH}" ip saddr {CLIENT} ip daddr {TARGET} meta l4proto {{ tcp, udp }} th dport {{ {ports} }} counter accept comment "{self.owner}"\n'
            with acquisition():
                self.fw4_rule_attempted = True
                command(["nft", "-f", "-"], input_text=rule)
                chain = command_json(["nft", "-j", "list", "chain", "inet", "fw4", "forward"])
                owned = [item["rule"] for item in chain["nftables"] if item.get("rule", {}).get("comment") == self.owner]
                require(len(owned) == 1, "missing or ambiguous owned forward rule")
                self.fw4_rule_handle = owned[0]["handle"]
            self.emit("firewall_control", handle=self.fw4_rule_handle, owner=self.owner, interface=HOST_VETH, source=CLIENT, destination=TARGET, ports=ports)
        with deadline(3), open("/proc/sys/net/ipv4/ip_forward", "w") as target:
            target.write("1\n")
        self.emit("network", external_ip=self.external_ip, external_link=self.external_link, netns_inode=self.namespace_inode, host_veth_ifindex=self.link_index, original_ip_forward=self.forwarding, nft_table=TABLE, nft_owner=self.owner)

    def stop_engine(self):
        if self.engine is None:
            if self.engine_stdio is not None:
                self.engine_stdio.close()
                self.engine_stdio = None
            return
        process = self.engine
        forced = stop_owned(process, self.engine_start)
        self.engine = None
        self.engine_start = None
        if self.engine_stdio is not None:
            self.engine_stdio.close()
            self.engine_stdio = None
        self.emit("engine_stopped", pid=process.pid, returncode=process.returncode, forced=forced)
        require(not forced and process.returncode == 0, "engine did not exit gracefully with status 0")

    def start_engine(self, pair, name):
        arm = self.manifest["arms"][name]
        verified_arm(arm)
        stem = self.assets / f"pair-{pair}.{name}"
        stdio = str(stem) + ".stdio.log"
        engine_log = str(stem) + ".engine.log"
        argv = [arm["binary"], "--config", arm["config"], "--log-file", engine_log]
        with acquisition():
            self.engine_stdio = open(stdio, "xb")
            self.engine = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.engine_stdio, stderr=subprocess.STDOUT, env=clean_environment(), start_new_session=True)
            self.engine_start = proc_stats(self.engine.pid)["starttime_ticks"]
        require(os.path.realpath(f"/proc/{self.engine.pid}/exe") == os.path.realpath(arm["binary"]), "running executable path mismatch")
        require(sha256_file(f"/proc/{self.engine.pid}/exe") == arm["sha256"], "running executable hash mismatch")
        end = time.monotonic() + 30
        last_error = "not listening"
        while time.monotonic() < end:
            require(self.engine.poll() is None, "engine exited before API readiness")
            try:
                require(api_owned(self.engine.pid, urlsplit(self.manifest["api"]["url"]).port), "API listener not owned by engine")
                version = api_request(self.manifest["api"], "/version")
                require(isinstance(version.get("version"), str) and version["version"].startswith("honk "), "unexpected API /version")
                require(proc_stats(self.engine.pid)["starttime_ticks"] == self.engine_start, "engine starttime changed")
                self.emit("engine_started", pair=pair, arm=name, pid=self.engine.pid, starttime_ticks=self.engine_start, argv=argv, exe_sha256=arm["sha256"], version=version, stdio_log=stdio, engine_log=engine_log)
                break
            except (ValueError, OSError, http.client.HTTPException) as exc:
                last_error = str(exc)
                time.sleep(0.25)
        else:
            raise TimeoutError(f"API not ready: {last_error}")
        self.emit("setup_settle", pair=pair, arm=name, phase="begin", duration_s=SETUP_SETTLE_SECONDS, outside_samples=True, reason="allow initial UDP health publication after API readiness")
        settle_started = time.perf_counter_ns()
        time.sleep(SETUP_SETTLE_SECONDS)
        self.emit("setup_settle", pair=pair, arm=name, phase="complete", duration_s=SETUP_SETTLE_SECONDS, elapsed_s=(time.perf_counter_ns() - settle_started) / 1_000_000_000, outside_samples=True)
        require(self.engine.poll() is None and proc_stats(self.engine.pid)["starttime_ticks"] == self.engine_start, "engine exited or changed identity during setup settle")

    def run_case(self, pair, arm_name, case):
        context = {"pair": pair, "arm": arm_name, "case": case["name"]}
        before = proc_stats(self.engine.pid)
        require(before["starttime_ticks"] == self.engine_start, "engine identity changed")
        stats_before = stats_snapshot(self.manifest["api"])
        self.emit("case_before", **context, process=before, stats=stats_before)
        spec = {"case": case, "netns_inode": self.namespace_inode, "netns_fd": self.namespace_fd, "expected_peers": [self.external_ip] if case["name"] == "direct" else [TARGET, "127.0.0.1"]}
        stem = self.assets / f"pair-{pair}.{arm_name}.{case['name']}"
        raw_path, stderr_path = str(stem) + ".client.jsonl", str(stem) + ".client.stderr"
        process = None
        client_error = None
        rows = []
        try:
            with open(raw_path, "x", encoding="utf-8") as raw, open(stderr_path, "x", encoding="utf-8") as stderr:
                try:
                    with acquisition():
                        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--client", json.dumps(spec)], stdin=subprocess.DEVNULL, stdout=raw, stderr=stderr, env=clean_environment(), start_new_session=True, pass_fds=(self.namespace_fd,))
                    process.wait(timeout=CLIENT_TIMEOUT)
                finally:
                    if process is not None:
                        stop_owned(process, grace=2)
        except Exception as exc:
            client_error = f"{type(exc).__name__}: {exc}"
        finally:
            if Path(raw_path).exists():
                for line in read_bytes(raw_path, 4 * 1024 * 1024).decode().splitlines():
                    try:
                        row = strict_json(line)
                        require(isinstance(row, dict), "invalid client row")
                    except ValueError as exc:
                        client_error = f"invalid client output: {exc}"
                        self.emit("client_record_error", **context, error=client_error)
                        continue
                    rows.append(row)
                    self.emit("attempt", **context, attempt=row)
            after = proc_stats(self.engine.pid)
            stats_after = stats_snapshot(self.manifest["api"])
            self.emit("case_after", **context, process=after, stats=stats_after, client_returncode=process.returncode if process is not None else None, client_error=client_error, raw_path=raw_path, stderr_path=stderr_path)
        require(after["starttime_ticks"] == before["starttime_ticks"] and after["utime_ticks"] >= before["utime_ticks"] and after["stime_ticks"] >= before["stime_ticks"], "invalid process counter transition")
        require(sha256_file(self.manifest["arms"][arm_name]["config"]) == self.manifest["arms"][arm_name]["config_sha256"], "config changed during case")
        summaries = summarize(rows, case)
        ok = client_error is None and process.returncode == 0 and all(row["ok"] for row in rows)
        self.completed_cases += 1
        self.failed_cases += not ok
        self.emit("case_summary", **context, ok=ok, summaries=summaries, unexpected_datagrams=sum(row["kind"] == "udp_unexpected" for row in rows), cpu_ticks_delta=after["utime_ticks"] + after["stime_ticks"] - before["utime_ticks"] - before["stime_ticks"], process_before=before, process_after=after, statistic_policy="medians/p95/rates are null if any attempt in that group failed; raw failures are retained")

    def run(self):
        for pair in range(1, self.manifest["runs"] + 1):
            order = ["baseline", "candidate"] if pair % 2 else ["candidate", "baseline"]
            self.emit("pair", pair=pair, order=order)
            for name in order:
                try:
                    self.start_engine(pair, name)
                    for case in [{"name": "direct", **self.manifest["direct"]}, *self.manifest["cases"]]:
                        self.run_case(pair, name, case)
                    verified_arm(self.manifest["arms"][name])
                    require(sha256_file(f"/proc/{self.engine.pid}/exe") == self.manifest["arms"][name]["sha256"], "running binary changed during arm")
                finally:
                    self.stop_engine()

    def cleanup(self):
        errors = []

        def attempt(label, action):
            try:
                action()
            except Exception as exc:
                errors.append(f"{label}: {type(exc).__name__}: {exc}")

        attempt("engine", self.stop_engine)
        if self.fw4_rule_attempted:
            def remove_forward_rule():
                chain = command_json(["nft", "-j", "list", "chain", "inet", "fw4", "forward"])
                owned = [item["rule"] for item in chain["nftables"] if item.get("rule", {}).get("comment") == self.owner]
                require(len(owned) <= 1, "ambiguous forward rule ownership")
                for rule in owned:
                    require(self.fw4_rule_handle is None or rule["handle"] == self.fw4_rule_handle, "forward rule identity changed; not deleting")
                    command(["nft", "delete", "rule", "inet", "fw4", "forward", "handle", str(rule["handle"])])
            attempt("forward_rule", remove_forward_rule)
        if self.table_attempted:
            def remove_table():
                tables = command_json(["nft", "-j", "list", "tables"])["nftables"]
                if not any(item.get("table", {}).get("name") == TABLE and item["table"]["family"] == "ip" for item in tables):
                    return
                table = command_json(["nft", "-j", "list", "table", "ip", TABLE])
                require(any(item.get("table", {}).get("comment") == self.owner for item in table["nftables"]), "nft ownership marker changed; not deleting")
                command(["nft", "delete", "table", "ip", TABLE])
            attempt("nft", remove_table)
        if self.link_attempted:
            def remove_link():
                links = command_json(["ip", "-j", "link", "show"])
                matches = [link for link in links if link["ifname"] == HOST_VETH]
                if not matches:
                    return
                link = matches[0]
                # Host link policy may rewrite aliases; preserve same-named replacements by ifindex.
                require(self.link_index is not None and link["ifindex"] == self.link_index, "veth identity changed; not deleting")
                command(["ip", "link", "delete", "dev", HOST_VETH])
            attempt("veth", remove_link)
        if self.namespace_inode is not None:
            def remove_namespace():
                require(os.stat(f"/var/run/netns/{NAMESPACE}").st_ino == self.namespace_inode, "namespace identity changed; not deleting")
                command(["ip", "netns", "delete", NAMESPACE])
            attempt("namespace", remove_namespace)
        if self.namespace_fd is not None:
            attempt("namespace_fd", lambda: os.close(self.namespace_fd))
        if self.forwarding is not None:
            def restore_forwarding():
                with deadline(3), open("/proc/sys/net/ipv4/ip_forward", "w") as target:
                    target.write(self.forwarding + "\n")
                require(read_bytes("/proc/sys/net/ipv4/ip_forward", 16).decode().strip() == self.forwarding, "ip_forward restore mismatch")
            attempt("ip_forward", restore_forwarding)
        for path, original in self.socket_limits.items():
            def restore_socket_limit(path=path, original=original):
                with deadline(3), open(path, "w") as target:
                    target.write(original + "\n")
                require(read_bytes(path, 32).decode().strip() == original, "socket limit restore mismatch")
            attempt(path, restore_socket_limit)
        if self.restore_service:
            def restore_service():
                command([self.manifest["service"], "start"], timeout=30)
                self.await_service(True)
                # OpenWrt's start script randomizes its subscription cron minute.
                cron = Path("/etc/crontabs/root")
                current = read_bytes(cron, 1024 * 1024).decode() if cron.exists() else None
                other_jobs = lambda text: [line for line in (text or "").splitlines() if "/etc/init.d/honk hot_reload" not in line]
                require(other_jobs(current) == other_jobs(self.service_cron), "unrelated cron entries changed; not overwriting")
                if self.service_cron is None:
                    if cron.exists():
                        command(["crontab", "-r"])
                else:
                    command(["crontab", "-"], input_text=self.service_cron)
                    require(read_bytes(cron, 1024 * 1024).decode() == self.service_cron, "cron restore mismatch")
            attempt("service", restore_service)
        self.emit("cleanup", ok=not errors, errors=errors, service_restore_required=self.restore_service)
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, help="New JSONL path; adjacent .assets directory must also not exist")
    parser.add_argument("--client", help=argparse.SUPPRESS)
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, alarm)
    for signum in STOP_SIGNALS:
        signal.signal(signum, interrupted)
    if args.client is not None:
        require(args.manifest is None and args.output is None, "--client is internal-only")
        return client_main(args.client)
    require(args.manifest is not None and args.output is not None, "--manifest and --output are required")
    require(os.geteuid() == 0 and sys.platform == "linux", "run as root on the Linux engine host")
    manifest, manifest_hash = load_manifest(args.manifest)
    output = args.output.absolute()
    assets = Path(str(output) + ".assets")
    require(output.parent.is_dir() and not os.path.lexists(output) and not os.path.lexists(assets), "output parent must exist; output/assets must not already exist")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as sink:
        assets.mkdir(mode=0o700)
        driver = Driver(manifest, sink, assets)
        error = None
        cleanup_errors = []
        try:
            require(stat.S_ISREG(os.fstat(sink.fileno()).st_mode), "output must be a regular file")
            driver.emit("identity", host=dict(zip(("sysname", "nodename", "release", "version", "machine"), os.uname())), clock_ticks_per_second=os.sysconf("SC_CLK_TCK"), python=sys.version, driver_sha256=sha256_file(__file__), manifest_sha256=manifest_hash, arms=manifest["arms"], cases=manifest["cases"], direct=manifest["direct"], target=TARGET, client=CLIENT, api_url=manifest["api"]["url"], runs=manifest["runs"], scope="real-core forwarded LAN IPv4; 15 sequential HTTP opens; 3 x 16 MiB HTTP and 3 x 16 MiB HTTPS downloads; 100 x 1200-byte UDP echoes per destination on one socket across two ports; HTTPS test certificate deliberately unverified; no full VLESS uplink, Internet or performance-threshold claim", identity_scope="binary/config/driver SHA256 measured; commits/build profiles are manifest-supplied labels, not inferred from executable bytes", cleanup_scope="owns only child process groups, client namespace/veth and scoped NAT table; preserves BPF pins/sequence; cannot restore after SIGKILL/power loss")
            driver.setup()
            driver.run()
        except (Exception, KeyboardInterrupt) as exc:
            error = f"{type(exc).__name__}: {exc}"
            driver.emit("error", error=error)
        finally:
            for signum in STOP_SIGNALS:
                signal.signal(signum, signal.SIG_IGN)
            cleanup_errors = driver.cleanup()
        expected_cases = 2 * manifest["runs"] * (1 + len(manifest["cases"]))
        complete = driver.completed_cases == expected_cases
        ok = error is None and not cleanup_errors and complete and driver.failed_cases == 0
        driver.emit("result", ok=ok, complete=complete, expected_cases=expected_cases, completed_cases=driver.completed_cases, failed_cases=driver.failed_cases, error=error, cleanup_errors=cleanup_errors)
        with deadline(5):
            os.fsync(sink.fileno())
        return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as exc:
        print(f"vless-datapath: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
