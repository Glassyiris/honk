#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run bench/lab-targets.py --bind 198.18.0.1 --ready FILE --trace FILE
# 3. Or: chmod +x bench/lab-targets.py && ./bench/lab-targets.py --help
# ─────────────────
from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import socket
import struct
import threading
import time
from typing import Final

HTTP_PORT: Final = 18080
UDP_PORT: Final = 15353
DNS_PORT: Final = 15354


def append_trace(path: Path, event: str, peer: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event": event, "peer": peer, "monotonicNs": time.monotonic_ns()}, sort_keys=True) + "\n")


def serve_http(listener: socket.socket, trace: Path, stopped: threading.Event) -> None:
    listener.settimeout(0.2)
    while not stopped.is_set():
        try:
            connection, peer = listener.accept()
        except TimeoutError:
            continue
        with connection:
            connection.settimeout(2)
            request = connection.recv(4096)
            append_trace(trace, "http", f"{peer[0]}:{peer[1]}")
            body = b"HONK-LAB-HTTP\n"
            if request.startswith(b"GET "):
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n" + body)


def serve_udp(sock: socket.socket, trace: Path, stopped: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stopped.is_set():
        try:
            payload, peer = sock.recvfrom(65535)
        except TimeoutError:
            continue
        append_trace(trace, "udp", f"{peer[0]}:{peer[1]}")
        sock.sendto(b"HONK-LAB-UDP:" + payload, peer)


def dns_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    offset = 12
    while offset < len(query) and query[offset] != 0:
        offset += query[offset] + 1
    question_end = offset + 5
    if question_end > len(query):
        return b""
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.42")
    return header + query[12:question_end] + answer


def serve_dns(sock: socket.socket, trace: Path, stopped: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stopped.is_set():
        try:
            query, peer = sock.recvfrom(4096)
        except TimeoutError:
            continue
        append_trace(trace, "dns", f"{peer[0]}:{peer[1]}")
        response = dns_response(query)
        if response:
            sock.sendto(response, peer)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stopped.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stopped.set())
    http = socket.socket()
    http.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    http.bind((args.bind, HTTP_PORT))
    http.listen(16)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.bind, UDP_PORT))
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind((args.bind, DNS_PORT))
    threads = [
        threading.Thread(target=serve_http, args=(http, args.trace, stopped)),
        threading.Thread(target=serve_udp, args=(udp, args.trace, stopped)),
        threading.Thread(target=serve_dns, args=(dns, args.trace, stopped)),
    ]
    for thread in threads:
        thread.start()
    args.ready.write_text("ready\n")
    stopped.wait()
    for resource in (http, udp, dns):
        resource.close()
    for thread in threads:
        thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
