#!/bin/bash
# hot-probe.sh PORT WARMUP SAMPLES — per-request timings through the engine.
set -u
port=$1 warm=${2:-5} samples=${3:-30}
for _ in $(seq 1 "$warm"); do
    ip netns exec lab curl -s -o /dev/null --max-time 5 "http://10.10.10.70:$port/" >/dev/null 2>&1
done
for _ in $(seq 1 "$samples"); do
    ip netns exec lab curl -s -o /dev/null \
        -w '%{time_connect} %{time_starttransfer} %{time_total}\n' \
        --max-time 5 "http://10.10.10.70:$port/" 2>/dev/null
done
