#!/usr/bin/env python3
# selection-targets.py — target "websites" + check-url responder for the
# group-selection lab. HTTP 200 on the site ports, HTTP 204 on the check
# port, UDP echo for liveness. One process serves them all.
from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import socket
import threading

SITE_PORTS = (9001, 9002, 9003)
CHECK_PORT = 80
UDP_PORT = 15353


def append_trace(path: Path, event: str, peer: str, port: int) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event": event, "peer": peer, "port": port}, sort_keys=True) + "\n")


def serve_http(listener: socket.socket, port: int, trace: Path, stopped: threading.Event) -> None:
    listener.settimeout(0.2)
    while not stopped.is_set():
        try:
            connection, peer = listener.accept()
        except TimeoutError:
            continue
        with connection:
            connection.settimeout(2)
            try:
                request = connection.recv(4096)
            except OSError:
                continue
            append_trace(trace, "http", f"{peer[0]}:{peer[1]}", port)
            if not request.startswith((b"GET ", b"HEAD ")):
                continue
            if port == CHECK_PORT:
                connection.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            else:
                body = f"SELECTION-LAB-SITE-{port}\n".encode()
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n" + body
                )


def serve_udp(sock: socket.socket, trace: Path, stopped: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stopped.is_set():
        try:
            payload, peer = sock.recvfrom(65535)
        except TimeoutError:
            continue
        append_trace(trace, "udp", f"{peer[0]}:{peer[1]}", UDP_PORT)
        sock.sendto(b"SELECTION-LAB-UDP:" + payload, peer)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stopped.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stopped.set())
    listeners: list[socket.socket] = []
    threads: list[threading.Thread] = []
    for port in (*SITE_PORTS, CHECK_PORT):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind, port))
        listener.listen(64)
        listeners.append(listener)
        threads.append(threading.Thread(target=serve_http, args=(listener, port, args.trace, stopped)))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.bind, UDP_PORT))
    threads.append(threading.Thread(target=serve_udp, args=(udp, args.trace, stopped)))
    for thread in threads:
        thread.start()
    args.ready.write_text("ready\n")
    stopped.wait()
    for listener in listeners:
        listener.close()
    udp.close()
    for thread in threads:
        thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
