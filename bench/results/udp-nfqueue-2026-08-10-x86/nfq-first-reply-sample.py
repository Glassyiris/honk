#!/usr/bin/env python3
import json
import math
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
samples = int(sys.argv[3])
warmup = int(sys.argv[4])


def exchange(record):
    payload = b"honk-nfq-first-reply"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    start = time.perf_counter_ns()
    try:
        sock.sendto(payload, (host, port))
        data, peer = sock.recvfrom(2048)
        elapsed = time.perf_counter_ns() - start
        if data != payload or peer != (host, port):
            return None
        return elapsed if record else 0
    except OSError:
        return None
    finally:
        sock.close()


for _ in range(warmup):
    exchange(False)
values = []
for _ in range(samples):
    value = exchange(True)
    if value is not None:
        values.append(value)
values.sort()


def percentile(p):
    if not values:
        return None
    return values[max(0, math.ceil(len(values) * p) - 1)] / 1000

result = {
    "samples": samples,
    "received": len(values),
    "loss": (samples - len(values)) / samples,
    "unit": "us",
    "p50": percentile(0.50),
    "p95": percentile(0.95),
    "p99": percentile(0.99),
    "max": None if not values else values[-1] / 1000,
}
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if len(values) == samples else 1)
