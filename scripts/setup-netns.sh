#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: run this script as root (sudo $0)" >&2
    exit 1
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "ERROR: iproute2 is required (the 'ip' command was not found)" >&2
    exit 1
fi

ensure_tun_device() {
    if [[ -c /dev/net/tun ]]; then
        return
    fi
    if [[ -e /dev/net/tun ]]; then
        echo "ERROR: /dev/net/tun exists but is not a character device" >&2
        exit 1
    fi
    if command -v modprobe >/dev/null 2>&1; then
        modprobe tun 2>/dev/null || true
    fi
    install -d -m 0755 /dev/net
    mknod -m 0666 /dev/net/tun c 10 200
    echo "Created /dev/net/tun for this environment"
}

ensure_tun_device

namespaces=(vpn-a vpn-router vpn-b)

cleanup_old_topology() {
    local namespace
    for namespace in "${namespaces[@]}"; do
        if ip netns list | awk '{print $1}' | grep -Fxq "${namespace}"; then
            ip netns delete "${namespace}"
        fi
    done
}

cleanup_on_error() {
    echo "ERROR: topology setup failed; removing the partial topology" >&2
    cleanup_old_topology
}

trap cleanup_on_error ERR
cleanup_old_topology

for namespace in "${namespaces[@]}"; do
    ip netns add "${namespace}"
    ip -n "${namespace}" link set lo up
done

ip link add veth-a type veth peer name veth-ra
ip link add veth-b type veth peer name veth-rb
ip link set veth-a netns vpn-a
ip link set veth-ra netns vpn-router
ip link set veth-b netns vpn-b
ip link set veth-rb netns vpn-router

ip -n vpn-a address add 192.168.10.2/24 dev veth-a
ip -n vpn-router address add 192.168.10.1/24 dev veth-ra
ip -n vpn-router address add 192.168.20.1/24 dev veth-rb
ip -n vpn-b address add 192.168.20.2/24 dev veth-b

ip -n vpn-a link set veth-a up
ip -n vpn-router link set veth-ra up
ip -n vpn-router link set veth-rb up
ip -n vpn-b link set veth-b up

ip -n vpn-a route add 192.168.20.0/24 via 192.168.10.1
ip -n vpn-b route add 192.168.10.0/24 via 192.168.20.1
ip netns exec vpn-router sysctl -q -w net.ipv4.ip_forward=1

trap - ERR
echo "PASS: created different-subnet underlay topology"
echo "  vpn-a      192.168.10.2/24"
echo "  vpn-router 192.168.10.1/24 <-> 192.168.20.1/24"
echo "  vpn-b      192.168.20.2/24"
