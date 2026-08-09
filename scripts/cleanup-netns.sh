#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: run this script as root (sudo $0)" >&2
    exit 1
fi

for namespace in vpn-a vpn-router vpn-b; do
    if ip netns list | awk '{print $1}' | grep -Fxq "${namespace}"; then
        ip netns delete "${namespace}"
        echo "Removed namespace ${namespace}"
    fi
done
echo "Network namespace cleanup complete"
