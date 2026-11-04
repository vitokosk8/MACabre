#!/usr/bin/env bash
# Isolated IGMP spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN, multicast snooping on) with two hosts attached:
#
#   attacker: a host that has joined no group. It sends one IGMP membership report for
#             GROUP with MACabre's module.
#   sender:   a host that is the source of GROUP. It is attached so the LAN is realistic;
#             the lab does not depend on its traffic.
#
# Phases:
#   Phase 1 (baseline): no report has been sent. The bridge should have no membership entry
#            for GROUP on the attacker's port.
#   Phase 2 (attack): the attacker sends one IGMP report for GROUP. The bridge should learn
#            GROUP on the attacker's port. The report is not authenticated, so the bridge
#            accepts a host's claim to a group it did not ask for.
#
# What the lab shows: that this bridge's snooping table gains the attacker's port for the
# group after an unauthenticated report. What it does not show:
#   - delivery of the group's traffic to the attacker. This kernel does not deliver a
#     registered group to a member port while that port has flooding of unknown multicast
#     turned off, so delivery cannot be measured here without changing the flag on the
#     very port under test. Test delivery on the target switch.
#   - vendor limits on groups per port, querier election, report suppression or logging.
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/igmp_spoofing_lab.sh
#
# Requirements: iproute2 (ip, bridge) and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
GROUP="239.1.2.3"
ATTACKER_MAC="02:00:00:00:00:20"
ATTACKER_IP="10.77.0.20"

stop_lab() {
    for ns in lan sender attacker; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add lan
ip netns add sender
ip netns add attacker

for pair in "snd:sender" "atk:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge mcast_snooping 1
ip netns exec lan ip link set br0 up
for name in snd atk; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec sender ip link set h-snd up
ip netns exec sender ip link set lo up
ip netns exec attacker ip link set h-atk address "$ATTACKER_MAC"
ip netns exec attacker ip link set h-atk up
ip netns exec attacker ip link set lo up

REPORT_CODE='
import os, threading
from macabre.attacks.igmp_spoofing import IgmpSpoofingConfig, run_igmp_spoofing
stats = run_igmp_spoofing(
    IgmpSpoofingConfig(iface="h-atk", source_mac=os.environ["ATTACKER_MAC"], groups=(os.environ["GROUP"],),
                       source_ip=os.environ["ATTACKER_IP"]),
    threading.Event(),
    lambda _s: None,
)
print(stats.reports)
'

# Prints the bridge's membership entries for GROUP on the attacker's port (empty when none).
attacker_entry() {
    ip netns exec lan bridge mdb show dev br0 2>/dev/null | grep "port p-atk" | grep "grp $GROUP" || true
}

echo "Phase 1: baseline, no report sent. Membership entry for $GROUP on the attacker's port:"
BASE="$(attacker_entry)"
if [[ -z "$BASE" ]]; then
    echo "  none"
else
    echo "  $BASE"
fi
echo

echo "Phase 2: the attacker sends one IGMP membership report for $GROUP with MACabre's module"
REPORTS="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    ATTACKER_IP="$ATTACKER_IP" GROUP="$GROUP" "$PY" -c "$REPORT_CODE" 2>/dev/null || echo 0)"
echo "  reports sent: $REPORTS"
sleep 1
AFTER="$(attacker_entry)"
if [[ -z "$AFTER" ]]; then
    echo "  membership entry on the attacker's port: none"
else
    echo "  membership entry on the attacker's port: $AFTER"
fi
echo

if [[ -z "$BASE" && -n "$AFTER" && "$REPORTS" == "1" ]]; then
    echo "Result: before the report the bridge had no entry for $GROUP on the attacker's port. After one unauthenticated IGMP report from that port, it learned $GROUP there. The snooping table trusts the report. Delivery of the group's traffic is not measured here; test it on the target switch."
    exit 0
elif [[ -z "$AFTER" ]]; then
    echo "Result: inconclusive. The bridge did not learn the group from the report on this kernel. Result unreliable."
    exit 2
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
