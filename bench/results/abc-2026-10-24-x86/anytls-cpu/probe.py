#!/usr/bin/env python3
"""Sample an engine's CPU ticks around one iperf3 run.

Prints one JSON line per repetition: iperf3's command wall, the harness-style
cores over that wall, and cores integrated over the transfer window reported
by iperf3. The sampler runs in a thread so the command wall stays real.
"""
import json
import subprocess
import sys
import threading
import time

pid = sys.argv[1]
port = sys.argv[2] if len(sys.argv) > 2 else "5205"
reps = int(sys.argv[3]) if len(sys.argv) > 3 else 1
clock = 100  # USER_HZ


def ticks():
    with open(f"/proc/{pid}/stat", encoding="ascii") as handle:
        fields = handle.read().split()
    return int(fields[13]) + int(fields[14])


for rep in range(reps):
    samples = []
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            samples.append((time.time(), ticks()))
            time.sleep(0.05)
        samples.append((time.time(), ticks()))

    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    ticks0 = ticks()
    start = time.time()
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "lab", "iperf3", "-c", "10.10.10.70",
         "-p", port, "-t", "8", "-R", "-J"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        out, err = proc.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = "", "timeout"
    wall = time.time() - start
    ticks1 = ticks()
    stop.set()
    thread.join(timeout=2)
    try:
        data = json.loads(out)
        timesecs = data["start"]["timestamp"]["timesecs"]
        duration = data["end"]["sum_received"]["seconds"]
        mbps = data["end"]["sum_received"]["bits_per_second"] / 1e6
    except Exception as error:  # noqa: BLE001
        print(json.dumps({"port": int(port), "rep": rep, "error": f"{error}", "stderr": err.strip()[:160], "wall": round(wall, 3)}))
        continue
    samples.sort()
    window = [(t, c) for t, c in samples if timesecs <= t <= timesecs + duration]
    xfer_cores = None
    if len(window) >= 2 and window[-1][0] > window[0][0]:
        xfer_cores = (window[-1][1] - window[0][1]) / clock / (window[-1][0] - window[0][0])
    print(json.dumps({
        "port": int(port),
        "rep": rep,
        "mbps": round(mbps, 1),
        "wall": round(wall, 3),
        "transfer_seconds": round(duration, 3),
        "cores_command": round((ticks1 - ticks0) / clock / wall, 3),
        "cores_transfer": None if xfer_cores is None else round(xfer_cores, 3),
        "samples": len(samples),
    }))
