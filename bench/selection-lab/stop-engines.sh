#!/bin/bash
# stop-engines.sh — kill honk/sing-box, rebuild netns if sing-box ran.
sb_running=$(pgrep -f "sing-bo[x] run" 2>/dev/null)
pkill -f "/root/hon[k]" 2>/dev/null
pkill -f "sing-bo[x] run" 2>/dev/null
for _ in $(seq 1 30); do
    pgrep -f "/root/hon[k]" >/dev/null && { sleep 1; continue; }
    pgrep -f "sing-bo[x] run" >/dev/null && { sleep 1; continue; }
    break
done
[ -n "$sb_running" ] && bash /root/setup-netns.sh >/dev/null 2>&1
exit 0
