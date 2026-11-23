#!/usr/bin/env bash
# Isolated IGMP query spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN, multicast snooping on) with two hosts attached:
#
#   attacker: sends IGMPv2 general queries from a low source address, with MACabre's module.
#   receiver: a host that joins no group. A capture on its port counts the IGMP queries it gets.
#
# Phases:
#   Phase 1 (baseline): no query is sent. The receiver's capture should show no IGMP query.
#   Phase 2 (attack): the attacker sends QUERIES general queries, one per second. The receiver's
#            capture should show every query the attacker sent, which means the LAN carries
#            queries from that port to the other hosts.
#
# What the lab shows: that queries sent from one port reach the other ports of this bridge
# (snooping on). What it does not show:
#   - whether any switch elects the attacker as querier. Querier election needs a segment with
#     a real querier and the switch under test: see the target-switch test in the technique page.
#   - whether a real switch accepts queries from an access port, or logs or drops them.
#   - whether receivers stop reporting or lose group membership, which depends on the hosts.
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/igmp_query_spoofing_lab.sh
#
# Requirements: iproute2 (ip, bridge), tcpdump, coreutils timeout, and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.
#
# Exit 0 when the receiver captured every query the attacker sent and none before the attack,
# 1 when queries were sent but the receiver captured fewer, and 2 when the baseline already shows
# queries or the tools are missing.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge tcpdump timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 2
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
ATTACKER_MAC="02:00:00:00:00:84"
ATTACKER_IP="10.0.0.1"
RECEIVER_IP="10.0.0.30"
QUERIES=3
INTERVAL=1.0
BASELINE_SECONDS=4
CAPTURE_SECONDS=8
CAPTURE_FILE="$PWD/igmp-query-receiver.txt"

stop_lab() {
    for ns in lan receiver attacker; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add lan
ip netns add receiver
ip netns add attacker

for pair in "rcv:receiver" "atk:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge mcast_snooping 1
ip netns exec lan ip link set br0 up
for name in rcv atk; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec receiver ip addr add "$RECEIVER_IP/24" dev h-rcv
ip netns exec receiver ip link set h-rcv up
ip netns exec receiver ip link set lo up
ip netns exec attacker ip link set h-atk address "$ATTACKER_MAC"
ip netns exec attacker ip link set h-atk up
ip netns exec attacker ip link set lo up

QUERY_CODE='
import os, threading
from macabre.attacks.igmp_query_spoofing import IgmpQuerySpoofingConfig, run_igmp_query_spoofing
stats = run_igmp_query_spoofing(
    IgmpQuerySpoofingConfig(
        iface="h-atk",
        source_mac=os.environ["ATTACKER_MAC"],
        source_ip=os.environ["ATTACKER_IP"],
        queries=int(os.environ["QUERIES"]),
        interval=float(os.environ["INTERVAL"]),
    ),
    threading.Event(),
    lambda _s: None,
)
print(stats.queries)
'

# Capture IGMP on the receiver's port for CAPTURE_SECONDS, in the background, into CAPTURE_FILE.
start_capture() {
    : > "$CAPTURE_FILE"
    ip netns exec receiver timeout "$CAPTURE_SECONDS" tcpdump -i h-rcv -n -l 'ip proto 2' > "$CAPTURE_FILE" 2>/dev/null &
    CAPTURE_PID=$!
    sleep 1
}

queries_captured() {
    grep -ci 'query' "$CAPTURE_FILE" || true
}

echo "Phase 1: baseline, no query sent. Capturing on the receiver for ${BASELINE_SECONDS}s"
start_capture
sleep "$BASELINE_SECONDS"
wait "$CAPTURE_PID" 2>/dev/null || true
BASE_COUNT="$(queries_captured)"
echo "  IGMP queries on the receiver's port: $BASE_COUNT"
echo

echo "Phase 2: attack, $QUERIES general queries from $ATTACKER_IP, one every ${INTERVAL}s, with MACabre's module"
start_capture
REPORTED="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    ATTACKER_IP="$ATTACKER_IP" QUERIES="$QUERIES" INTERVAL="$INTERVAL" \
    "$PY" -c "$QUERY_CODE" 2>/dev/null || echo 0)"
echo "  queries sent: $REPORTED"
wait "$CAPTURE_PID" 2>/dev/null || true
ATTACK_COUNT="$(queries_captured)"
echo "  IGMP queries on the receiver's port: $ATTACK_COUNT"
echo "  raw capture (first lines):"
head -n 6 "$CAPTURE_FILE" | sed 's/^/    /'
echo

if [[ "$BASE_COUNT" != "0" ]]; then
    echo "Control: the receiver already saw IGMP queries before the attack. Result unreliable."
    exit 2
fi
if [[ "$REPORTED" == "$QUERIES" && "$ATTACK_COUNT" -ge "$QUERIES" ]]; then
    echo "Result: the receiver captured $ATTACK_COUNT IGMP queries from the attacker's port after $REPORTED were sent, and none before. Queries from an access port reach the other ports of this bridge. Querier election is not tested here; see the target-switch test."
    exit 0
fi
echo "Result: the receiver captured $ATTACK_COUNT of $REPORTED queries sent. Not validated."
exit 1
