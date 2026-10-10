#!/bin/bash
set -euo pipefail
ip netns del lab 2>/dev/null || true
ip link del veth-lab 2>/dev/null || true
ip netns add lab
ip link add veth-lab type veth peer name veth-client
ip address add 192.168.222.1/24 dev veth-lab
ip link set veth-lab up
ip link set veth-client netns lab
ip -n lab link set lo up
ip -n lab address add 192.168.222.2/24 dev veth-client
ip -n lab link set veth-client up
ip -n lab route add default via 192.168.222.1
sysctl -qw net.ipv4.ip_forward=1
