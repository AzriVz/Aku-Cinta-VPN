#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: run this script as root (sudo $0)" >&2
    exit 1
fi
for command in ip python3 curl sha256sum dd; do
    command -v "${command}" >/dev/null 2>&1 || { echo "ERROR: '${command}' is required" >&2; exit 1; }
done

ip -n vpn-a link show tun0 >/dev/null
ip -n vpn-b link show tun0 >/dev/null

WORK_DIR=$(mktemp -d /tmp/aku-cinta-vpn-transfer.XXXXXX)
SERVER_DIR="${WORK_DIR}/server"
CLIENT_DIR="${WORK_DIR}/client"
mkdir -p "${SERVER_DIR}" "${CLIENT_DIR}"
SERVER_PID=""

cleanup() {
    if [[ -n ${SERVER_PID} ]]; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT INT TERM

SOURCE_FILE="${SERVER_DIR}/vpn-test-5mb.bin"
DEST_FILE="${CLIENT_DIR}/vpn-test-5mb.bin"
dd if=/dev/urandom of="${SOURCE_FILE}" bs=1M count=5 status=none
SOURCE_HASH=$(sha256sum "${SOURCE_FILE}" | awk '{print $1}')

ip netns exec vpn-b python3 -m http.server 8080 \
    --bind 10.8.0.2 \
    --directory "${SERVER_DIR}" \
    >"${WORK_DIR}/http-server.log" 2>&1 &
SERVER_PID=$!

downloaded=false
for _attempt in 1 2 3 4 5; do
    if ip netns exec vpn-a curl --fail --silent --show-error \
        --connect-timeout 2 --max-time 60 \
        --output "${DEST_FILE}" \
        http://10.8.0.2:8080/vpn-test-5mb.bin; then
        downloaded=true
        break
    fi
    sleep 1
done
if [[ ${downloaded} != true ]]; then
    echo "ERROR: download through 10.8.0.2 failed" >&2
    cat "${WORK_DIR}/http-server.log" >&2 || true
    exit 1
fi

DEST_HASH=$(sha256sum "${DEST_FILE}" | awk '{print $1}')
if [[ ${SOURCE_HASH} != "${DEST_HASH}" ]]; then
    echo "FAIL: SHA-256 mismatch" >&2
    echo "source:      ${SOURCE_HASH}" >&2
    echo "destination: ${DEST_HASH}" >&2
    exit 1
fi

echo "PASS: 5 MB file transferred successfully through VPN address 10.8.0.2"
echo "PASS: SHA-256 hashes match (${SOURCE_HASH})"
