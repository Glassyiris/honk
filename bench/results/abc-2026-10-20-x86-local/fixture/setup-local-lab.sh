#!/bin/bash
set -euo pipefail
ROOT=/root/bench-20261020
FB=$ROOT/fixture
SING=$ROOT/bin/sing-box
ANYTLS=$ROOT/bin/anytls-server
mkdir -p "$FB/www" "$ROOT/state-honk" "$ROOT/stability"
[ -s /root/labsrv/cert.pem ] || {
  mkdir -p /root/labsrv
  openssl req -x509 -newkey rsa:2048 -nodes -keyout /root/labsrv/key.pem \
    -out /root/labsrv/cert.pem -days 3650 -subj "/CN=hy2.test" >/dev/null 2>&1
}

# local target netns, replaces the unavailable 10.10.10.70 fixture
ip netns del labsrv 2>/dev/null || true
ip link del veth-srv 2>/dev/null || true
ip netns add labsrv
ip link add veth-srv type veth peer name veth-srvp
ip addr add 192.168.223.1/24 dev veth-srv
ip link set veth-srv up
ip link set veth-srvp netns labsrv
ip netns exec labsrv ip addr add 192.168.223.2/24 dev veth-srvp
ip netns exec labsrv ip link set veth-srvp up
ip netns exec labsrv ip link set lo up
ip netns exec labsrv ip route add default via 192.168.223.1
sysctl -qw net.ipv4.ip_forward=1
ip netns exec lab ip route replace 192.168.223.0/24 via 192.168.222.1 2>/dev/null || true

pkill -f "$SING run -c $FB/singbox-server.json" 2>/dev/null || true
pkill -f "$ANYTLS" 2>/dev/null || true
pkill -f "$FB/target-fixture.py" 2>/dev/null || true
sleep 1

ip netns exec labsrv nohup "$SING" run -c "$FB/singbox-server.json" >"$FB/singbox-server.log" 2>&1 &
ip netns exec labsrv nohup "$ANYTLS" -l 0.0.0.0:2443 -p testpass123 >"$FB/anytls-server.log" 2>&1 &
ip netns exec labsrv nohup python3 "$FB/target-fixture.py" >"$FB/target.log" 2>&1 &
for p in 5201 5202 5203 5204 5205 5206 5300; do
  ip netns exec labsrv iperf3 -s -D -p "$p"
done
sleep 2
ip netns exec labsrv ss -tlnp | grep -E ':(8443|2444|2447|2446|2445|2443|8080|800[1-6]|520[1-6]|5300) ' | sort
ip netns exec labsrv ss -ulnp | grep -E ':(5353[1-6]|53539) ' | sort
