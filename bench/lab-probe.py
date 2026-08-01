#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run bench/lab-probe.py --relay IP:PORT --target IP --output FILE
# 3. Or: chmod +x bench/lab-probe.py && ./bench/lab-probe.py --help
# ─────────────────
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import struct
import time
from typing import Final

HTTP_PORT: Final = 18080
UDP_PORT: Final = 15353
DNS_PORT: Final = 15354


def exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def socks_connect(relay: tuple[str, int], target: tuple[str, int]) -> socket.socket:
    connection = socket.create_connection(relay, timeout=3)
    connection.sendall(b"\x05\x01\x00")
    if exact(connection, 2) != b"\x05\x00":
        raise ConnectionError("SOCKS authentication negotiation failed")
    connection.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1]))
    response = exact(connection, 10)
    if response[:2] != b"\x05\x00":
        raise ConnectionError("SOCKS connect failed")
    return connection


def udp_associate(relay: tuple[str, int]) -> tuple[socket.socket, socket.socket, tuple[str, int]]:
    control = socket.create_connection(relay, timeout=3)
    control.sendall(b"\x05\x01\x00")
    if exact(control, 2) != b"\x05\x00":
        raise ConnectionError("SOCKS authentication negotiation failed")
    control.sendall(b"\x05\x03\x00\x01\0\0\0\0\0\0")
    response = exact(control, 10)
    if response[:2] != b"\x05\x00":
        raise ConnectionError("SOCKS UDP associate failed")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 0))
    udp.settimeout(3)
    host = socket.inet_ntoa(response[4:8])
    if host == "0.0.0.0":
        host = relay[0]
    return control, udp, (host, struct.unpack("!H", response[8:10])[0])


def packet(target: tuple[str, int], payload: bytes) -> bytes:
    return b"\0\0\0\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1]) + payload


def dns_query() -> bytes:
    return bytes.fromhex("12340100000100000000000006676f6f676c6503636f6d0000010001")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    relay_host, relay_port = args.relay.rsplit(":", 1)
    relay = (relay_host, int(relay_port))
    started = time.monotonic_ns()
    tcp = socks_connect(relay, (args.target, HTTP_PORT))
    with tcp:
        tcp.sendall(b"GET / HTTP/1.1\r\nHost: lab.invalid\r\nConnection: close\r\n\r\n")
        http = b""
        while chunk := tcp.recv(4096):
            http += chunk
    control, udp, udp_relay = udp_associate(relay)
    with control, udp:
        udp.sendto(packet((args.target, UDP_PORT), b"probe"), udp_relay)
        udp_reply = udp.recv(4096)
        udp.sendto(packet((args.target, DNS_PORT), dns_query()), udp_relay)
        dns_reply = udp.recv(4096)
    result = {
        "schema": 1,
        "relay": args.relay,
        "tcp": {"ok": b"HONK-LAB-HTTP" in http},
        "udp": {"ok": b"HONK-LAB-UDP:probe" in udp_reply, "relayMarker": udp_reply[-1:].decode()},
        "dns": {"ok": b"\xc0\x0c\x00\x01\x00\x01" in dns_reply, "transactionId": dns_reply[10:12].hex()},
        "elapsedUs": (time.monotonic_ns() - started) // 1000,
    }
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if all(result[name]["ok"] for name in ("tcp", "udp", "dns")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
