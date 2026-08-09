#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: run this script as root (sudo $0)" >&2
    exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
BINARY="${PROJECT_DIR}/bin/aku-cinta-vpn"
KEY_FILE="${PROJECT_DIR}/vpn.key"

[[ -x ${BINARY} ]] || { echo "ERROR: ${BINARY} is missing; run 'make build'" >&2; exit 1; }
[[ -r ${KEY_FILE} ]] || { echo "ERROR: ${KEY_FILE} is missing; run 'make key'" >&2; exit 1; }

exec ip netns exec vpn-a "${BINARY}" \
    --tun tun0 \
    --tun-ip 10.8.0.1/24 \
    --listen 192.168.10.2:51820 \
    --peer 192.168.20.2:51820 \
    --key "${KEY_FILE}" \
    --mtu 1300 \
    "$@"
