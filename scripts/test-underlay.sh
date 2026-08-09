#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: run this script as root (sudo $0)" >&2
    exit 1
fi

echo "Testing vpn-a (192.168.10.0/24) -> vpn-b (192.168.20.0/24)..."
ip netns exec vpn-a ping -c 3 -W 2 192.168.20.2
echo "Testing reverse underlay route..."
ip netns exec vpn-b ping -c 3 -W 2 192.168.10.2
echo "PASS: endpoints communicate through vpn-router across different underlay subnets"
