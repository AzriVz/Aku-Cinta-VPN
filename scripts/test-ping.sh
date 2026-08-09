#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: run this script as root (sudo $0)" >&2
    exit 1
fi

ip -n vpn-a link show tun0 >/dev/null
ip -n vpn-b link show tun0 >/dev/null

echo "Testing encrypted overlay vpn-a (10.8.0.1) -> vpn-b (10.8.0.2)..."
ip netns exec vpn-a ping -c 4 -W 3 10.8.0.2
echo "Testing encrypted overlay in reverse..."
ip netns exec vpn-b ping -c 4 -W 3 10.8.0.1
echo "PASS: bidirectional ICMP traversed the encrypted VPN overlay"
