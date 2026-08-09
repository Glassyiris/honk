#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request

ROOT = Path("/root/nfq-bench-1c06f44")
BIN = ROOT / "honk-core"
API = "http://127.0.0.1:9090"
OUTPUT = ROOT / "first-reply.jsonl"
SEQUENCE = ("off", "on", "on", "off", "off", "on", "on", "off", "off", "on")
SAMPLES = 1000
WARMUP = 20


def stop_candidate():
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            target = (entry / "exe").resolve()
        except OSError:
            continue
        if target == BIN:
            os.kill(int(entry.name), signal.SIGTERM)
    for _ in range(300):
        alive = False
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                alive |= (entry / "exe").resolve() == BIN
            except OSError:
                pass
        if not alive:
            return
        time.sleep(0.1)
    raise RuntimeError("candidate did not stop")


def wait_api():
    for _ in range(300):
        try:
            with urllib.request.urlopen(API + "/version", timeout=1):
                return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("candidate API did not become ready")


def nfq_stats():
    with urllib.request.urlopen(API + "/stats", timeout=3) as response:
        return json.load(response)["udp"]["nfqueue"]


def counter_delta(before, after):
    return {key: after[key] - before[key] for key in before if isinstance(before[key], int)}


stop_candidate()
OUTPUT.write_text("")
arm_runs = {"off": 0, "on": 0}
try:
    for arm in SEQUENCE:
        arm_runs[arm] += 1
        run = arm_runs[arm]
        log_path = ROOT / f"first-reply-{arm}-{run}.engine.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [str(BIN), "--config", str(ROOT / f"honk-nfq-first-{arm}.dae")],
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                wait_api()
                time.sleep(2)
                before = nfq_stats()
                sample = subprocess.run(
                    ["ip", "netns", "exec", "lab", "python3", str(ROOT / "nfq-first-reply-sample.py"), "10.10.10.70", "53531", str(SAMPLES), str(WARMUP)],
                    text=True,
                    capture_output=True,
                    timeout=120,
                )
                after = nfq_stats()
                measured = json.loads(sample.stdout)
                delta = counter_delta(before, after)
                valid = sample.returncode == 0 and measured["received"] == SAMPLES
                if arm == "on":
                    valid &= delta["received"] >= int(SAMPLES * 0.98) and delta["proxyCopied"] >= int(SAMPLES * 0.98)
                else:
                    valid &= delta["received"] == 0 and delta["proxyCopied"] == 0
                valid &= all(delta[key] == 0 for key in ("drop", "cancel", "tokenMismatch", "tokenExhaustion", "verdictErrors"))
                row = {"schema": 1, "arm": arm, "run": run, "valid": bool(valid), "measurement": measured, "nfqueueDelta": delta, "samplerStderr": sample.stderr.strip()}
                with OUTPUT.open("a") as output:
                    output.write(json.dumps(row, sort_keys=True) + "\n")
                print(json.dumps(row, sort_keys=True), flush=True)
                if not valid:
                    raise RuntimeError(f"invalid {arm} run {run}")
            finally:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
finally:
    stop_candidate()
