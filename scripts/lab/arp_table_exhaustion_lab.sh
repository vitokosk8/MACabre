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
# The kernel's own neighbor table limit (gc_thresh3) is not set or read here: the VM kernel does not
# expose it. The lab observes the table instead:
#
#   Phase 0 (baseline): the victim pings the gateway, so it holds a legitimate entry for it.
#   Phase 1 (exhaustion): one burst of FRAMES requests from new senders. Then the victim's entry count
#                         is sampled every second for SAMPLE_SECONDS.
#
# Result: the peak entry count seen during the sampling, the sustained level (median of the last 30
# samples), and whether the gateway's entry survived. The kernel may evict entries under pressure, so a
# peak is not a configured limit. Other systems use other limits and eviction rules; test the target device.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/arp_table_exhaustion_lab.sh
#   sudo FRAMES=600 SAMPLE_SECONDS=30 scripts/lab/arp_table_exhaustion_lab.sh
#
# Exit 0 when the flood adds fake entries and raises the victim's table above its baseline. Exit 1 when
# the setup or the baseline did not match.
#
# Requirements: iproute2 (ip, bridge), ping, and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge ping sort; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-1100}"
RATE="${RATE:-100}"
SAMPLE_SECONDS="${SAMPLE_SECONDS:-60}"
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

# Sends FRAMES requests for the victim's address, from new fake senders in SENDER_SUBNET, at RATE per second.
SEND_CODE='
import os, threading
from macabre.attacks.arp_table_exhaustion import ArpTableExhaustionConfig, run_arp_table_exhaustion
run_arp_table_exhaustion(
    ArpTableExhaustionConfig(iface="h-att", victim_ip=os.environ["VICTIM_IP"], subnet=os.environ["SENDER_SUBNET"],
                             rate=int(os.environ["RATE"]), count=int(os.environ["FRAMES"])),
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

echo "Phase 1: exhaustion, $FRAMES requests for $VICTIM_IP at $RATE/s from new senders in $SENDER_SUBNET"
ip netns exec attacker env PYTHONPATH="$ROOT/src" VICTIM_IP="$VICTIM_IP" SENDER_SUBNET="$SENDER_SUBNET" \
    FRAMES="$FRAMES" RATE="$RATE" "$PY" -c "$SEND_CODE" >/dev/null 2>&1
echo "Sampling the victim's table every second for $SAMPLE_SECONDS s:"
SAMPLES="$WORK/samples"
: > "$SAMPLES"
for s in $(seq 1 "$SAMPLE_SECONDS"); do
    cur="$(entries)"
    echo "$cur" >> "$SAMPLES"
    if (( s % 10 == 0 )); then
        echo "  t=${s}s: $cur entries"
    fi
    sleep 1
done
echo

PEAK="$(sort -n "$SAMPLES" | tail -1)"
SUSTAINED="$(tail -30 "$SAMPLES" | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')"
AFTER_FAKE="$(fake_entries)"
AFTER_GATEWAY="$(gateway_entry)"
echo "  peak entries in the victim's table: $PEAK"
echo "  sustained level (median of the last 30 s): $SUSTAINED"
echo "  fake sender entries left at the end: $AFTER_FAKE"
echo "  gateway entry present: $([[ "$AFTER_GATEWAY" -gt 0 ]] && echo yes || echo no)"
echo

if [[ "$BASE_GATEWAY" -gt 0 && "$AFTER_FAKE" -gt 0 && "$PEAK" -gt "$BASE_ENTRIES" ]]; then
    if [[ "$AFTER_GATEWAY" -gt 0 ]]; then
        GW_NOTE="The gateway's entry survived the flood."
    else
        GW_NOTE="The gateway's entry was evicted by the flood."
    fi
    echo "Result: the flood raised the victim's table to a peak of $PEAK entries, and it settled at about $SUSTAINED. $GW_NOTE The kernel may evict entries under pressure, so these numbers are observations, not a configured limit. Other systems use other limits and eviction rules; test the target device."
    exit 0
fi
echo "Result: the outcome did not match the expected phases. Result unreliable."
exit 1
