#!/bin/bash
# Lab client namespace on 10.10.10.50: traffic from netns "lab" flows through
# honk's lan interface (veth-lab).
set -e
ip netns del lab 2>/dev/null || true
ip link del veth-lab 2>/dev/null || true
ip netns add lab
ip link add veth-lab type veth peer name veth-client
ip addr add 192.168.222.1/24 dev veth-lab
ip link set veth-lab up
ip link set veth-client netns lab
ip netns exec lab ip addr add 192.168.222.2/24 dev veth-client
ip netns exec lab ip link set veth-client up
ip netns exec lab ip link set lo up
ip netns exec lab ip route add default via 192.168.222.1
echo "lab netns ready: client 192.168.222.2 -> gateway 192.168.222.1 (veth-lab)"
