#!/bin/bash
# Idempotent NAT for the lab client subnet (oif end0 on 10.10.10.43).
nft list table ip labnat >/dev/null 2>&1 && exit 0
nft add table ip labnat
nft 'add chain ip labnat post { type nat hook postrouting priority 100; }'
nft add rule ip labnat post oifname "enxbada2e0076a1" ip saddr 192.168.222.0/24 masquerade
echo nat-ready
