#!/usr/bin/env python3
# selection-relay.py — SOCKS5 relay with a runtime-controllable delay profile.
#
# Sibling of lab-socks5.py for the group-selection lab: the delay model is
# re-read from a JSON control file on every accepted connection, so a driver
# can flip node quality mid-run without restarting the relay:
#
#   {
#     "delay_ms": 20,                  # base one-way response delay
#     "per_target_ms": {"9001": 60},   # override by target port
#     "jitter_ms": 10,                 # uniform [0, jitter) added per response
#     "drop_rate": 0.3                 # probability of closing before greeting
#   }
#
# Delay semantics match lab-socks5.py: the sleep happens on upstream→client
# data, so `delay_ms` adds roughly that much to each response/RTT.
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import random
import selectors
import signal
import socket
import struct
import threading
import time


def read_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        result.extend(chunk)
    return bytes(result)


def read_address(connection: socket.socket) -> tuple[str, int]:
    atyp = read_exact(connection, 1)[0]
    if atyp == 1:
        host = socket.inet_ntoa(read_exact(connection, 4))
    elif atyp == 3:
        host = read_exact(connection, read_exact(connection, 1)[0]).decode("ascii")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, read_exact(connection, 16))
    else:
        raise ConnectionError("unsupported address type")
    return host, struct.unpack("!H", read_exact(connection, 2))[0]


def encode_address(host: str, port: int) -> bytes:
    try:
        return b"\x01" + socket.inet_aton(host) + struct.pack("!H", port)
    except OSError:
        encoded = host.encode("ascii")
        return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port)


class Profile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.mtime = 0.0
        self.data: dict = {}

    def current(self) -> dict:
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            return self.data
        if mtime != self.mtime:
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
                self.mtime = mtime
            except (OSError, json.JSONDecodeError):
                pass
        return self.data

    def delay_for(self, target_port: int) -> float:
        data = self.current()
        delay = float(data.get("per_target_ms", {}).get(str(target_port), data.get("delay_ms", 0)))
        jitter = float(data.get("jitter_ms", 0))
        if jitter > 0:
            delay += random.uniform(0, jitter)
        return delay / 1000

    def drop_rate(self) -> float:
        return float(self.current().get("drop_rate", 0))


def trace(path: Path, relay_id: str, protocol: str, target: tuple[str, int]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"relay": relay_id, "protocol": protocol, "target": f"{target[0]}:{target[1]}", "monotonicNs": time.monotonic_ns()}, sort_keys=True) + "\n")


def relay_tcp(client: socket.socket, upstream: socket.socket, delay: float) -> None:
    selector = selectors.DefaultSelector()
    sockets: dict[int, socket.socket] = {client.fileno(): client, upstream.fileno(): upstream}
    destinations: dict[int, socket.socket] = {client.fileno(): upstream, upstream.fileno(): client}
    selector.register(client.fileno(), selectors.EVENT_READ)
    selector.register(upstream.fileno(), selectors.EVENT_READ)
    while selector.get_map():
        for key, _mask in selector.select(timeout=2):
            source = sockets[key.fd]
            data = source.recv(65535)
            if not data:
                selector.close()
                return
            if source is upstream and delay > 0:
                time.sleep(delay)
            destinations[key.fd].sendall(data)


def udp_loop(sock: socket.socket, client_host: str, relay_id: str, profile: Profile, trace_path: Path, stopped: threading.Event) -> None:
    client_peer: tuple[str, int] | None = None
    sock.settimeout(0.2)
    while not stopped.is_set():
        try:
            packet, peer = sock.recvfrom(65535)
        except TimeoutError:
            continue
        if peer[0] == client_host and len(packet) >= 10 and packet[:3] == b"\0\0\0":
            client_peer = peer
            cursor = memoryview(packet)[3:]
            atyp = cursor[0]
            if atyp != 1:
                continue
            host = socket.inet_ntoa(cursor[1:5])
            port = struct.unpack("!H", cursor[5:7])[0]
            trace(trace_path, relay_id, "udp", (host, port))
            sock.sendto(cursor[7:], (host, port))
        elif client_peer is not None:
            delay = profile.delay_for(peer[1])
            if delay > 0:
                time.sleep(delay)
            sock.sendto(b"\0\0\0" + encode_address(peer[0], peer[1]) + packet + b":" + relay_id.encode(), client_peer)


def trace_error(path: Path, relay_id: str, stage: str, detail: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"relay": relay_id, "error": stage, "detail": detail, "monotonicNs": time.monotonic_ns()}, sort_keys=True) + "\n")


def handle_client(client: socket.socket, peer: tuple[str, int], relay_id: str, profile: Profile, trace_path: Path, stopped: threading.Event) -> None:
    with client:
        if profile.drop_rate() > 0 and random.random() < profile.drop_rate():
            trace_error(trace_path, relay_id, "dropped", "drop_rate")
            return
        try:
            version, methods = read_exact(client, 2)
        except (ConnectionError, OSError) as error:
            trace_error(trace_path, relay_id, "read-greeting", repr(error))
            return
        if version != 5:
            trace_error(trace_path, relay_id, "greeting", f"version={version}")
            return
        try:
            read_exact(client, methods)
            client.sendall(b"\x05\x00")
            version, command, reserved = read_exact(client, 3)
        except (ConnectionError, OSError) as error:
            trace_error(trace_path, relay_id, "read-request-header", repr(error))
            return
        if (version, reserved) != (5, 0):
            trace_error(trace_path, relay_id, "request", f"version={version} rsv={reserved}")
            return
        try:
            target = read_address(client)
        except (ConnectionError, OSError) as error:
            trace_error(trace_path, relay_id, "read-address", repr(error))
            return
        delay = profile.delay_for(target[1])
        if command == 1:
            upstream = socket.create_connection(target, timeout=2)
            with upstream:
                trace(trace_path, relay_id, "tcp", target)
                # Delay the CONNECT reply as well: engines that time only the
                # dial leg (honk health check) and engines that time the full
                # request (sing-box urltest) must both observe node quality.
                if delay > 0:
                    time.sleep(delay)
                client.sendall(b"\x05\x00\x00" + encode_address("0.0.0.0", 0))
                relay_tcp(client, upstream, delay)
        elif command == 3:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("0.0.0.0", 0))
            host, port = udp.getsockname()
            client.sendall(b"\x05\x00\x00" + encode_address(host, port))
            udp_loop(udp, peer[0], relay_id, profile, trace_path, stopped)
            udp.close()
        else:
            client.sendall(b"\x05\x07\x00" + encode_address("0.0.0.0", 0))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--relay-id", required=True)
    parser.add_argument("--control", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    args = parser.parse_args()
    profile = Profile(args.control)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stopped.set())
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(64)
    listener.settimeout(0.2)
    args.ready.write_text("ready\n")
    workers: list[threading.Thread] = []
    while not stopped.is_set():
        try:
            client, peer = listener.accept()
        except TimeoutError:
            continue
        worker = threading.Thread(target=handle_client, args=(client, peer, args.relay_id, profile, args.trace, stopped))
        worker.start()
        workers.append(worker)
    listener.close()
    for worker in workers:
        worker.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
