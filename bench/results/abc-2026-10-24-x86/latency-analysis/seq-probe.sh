#!/bin/bash
# seq-probe.sh PORT COUNT — per-request totals with no warmup, fresh engine.
set -u
port=$1 count=${2:-20}
for i in $(seq 1 "$count"); do
    ip netns exec lab curl -s -o /dev/null -w "$i %{time_total}\n" \
        --max-time 5 "http://10.10.10.70:$port/" 2>/dev/null
done
