#!/usr/bin/env bash
# Isolated unauthorized mini-switch / hub lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   lan (bridge br0) --(p-seg / h-seg veth)-- seg
#   seg (bridge br1, a hub: no learning needed) with two hosts behind it:
#     victim:   the authorized device on the access port.
#     attacker: the unauthorized mini-switch. Frames from the devices behind it go through it.
#   The LAN switch's access port is p-seg.
#
# Phases:
#   Phase 1 (baseline): only the authorized device sends. The switch should learn one MAC
#            on the access port.
#   Phase 2 (attack): the mini-switch passes frames from three devices, the authorized one
#            and two more. The switch should learn all three MACs on the same access port.
#
# What the lab shows: that this bridge learns several client MACs on one access port when a
# hub or mini-switch sits behind it. It does not enforce a limit or an authenticator's
# policy: the Linux bridge has no port security or 802.1X, so the violation action that a
# real switch takes is not reproduced. Nothing here touches the host's real network
# interfaces.
#
# Usage:
#   sudo scripts/lab/unauthorized_mini_switch_lab.sh
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
VICTIM_MAC="02:00:00:00:00:10"
ATTACKER_MAC="02:00:00:00:00:20"
CLIENT_2="02:00:00:00:00:11"
CLIENT_3="02:00:00:00:00:12"

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

ip link add p-seg type veth peer name h-seg
ip link set p-seg netns lan
ip link set h-seg netns seg

ip link add s-vic type veth peer name h-vic
ip link set s-vic netns seg
ip link set h-vic netns victim
ip link add s-atk type veth peer name h-atk
ip link set s-atk netns seg
ip link set h-atk netns attacker

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
ip netns exec lan ip link set p-seg master br0
ip netns exec lan ip link set p-seg up

ip netns exec seg ip link add br1 type bridge
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

# Counts the MACs the LAN bridge has learned on the access port, from the dynamic table.
learned_macs() {
    ip netns exec lan bridge fdb show br br0 dev p-seg 2>/dev/null \
        | grep -v permanent | grep -E "^02:00:00:00:00:1" | awk '{print $1}' | sort -u | wc -l
}

learned_list() {
    ip netns exec lan bridge fdb show br br0 dev p-seg 2>/dev/null \
        | grep -v permanent | grep -E "^02:00:00:00:00:1" | awk '{print $1}' | sort -u | tr '\n' ' '
}

SEND_CODE='
import os
from macabre.attacks.unauthorized_mini_switch import MiniSwitchConfig, run_mini_switch
import threading
stats = run_mini_switch(
    MiniSwitchConfig(iface="h-atk", client_macs=tuple(os.environ["CLIENTS"].split(","))),
    threading.Event(),
    lambda _s: None,
)
print(stats.frames)
'

echo "Phase 1: baseline, only the authorized device sends through the access port"
ip netns exec victim env PYTHONPATH="$ROOT/src" "$PY" -c "
from scapy.all import sendp
from scapy.all import Ether, Raw
sendp([Ether(src='$VICTIM_MAC', dst='ff:ff:ff:ff:ff:ff')/Raw(b'authorized')]*3, iface='h-vic', inter=0.1, verbose=False)
" 2>/dev/null || true
sleep 1
BASE_COUNT="$(learned_macs)"
echo "  MACs learned on the access port: $BASE_COUNT ($(learned_list))"
echo

echo "Phase 2: the mini-switch passes frames from three devices through the same access port"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" CLIENTS="$VICTIM_MAC,$CLIENT_2,$CLIENT_3" \
    "$PY" -c "$SEND_CODE" 2>/dev/null || echo 0)"
echo "  frames sent by the mini-switch: $SENT"
sleep 1
ATTACK_COUNT="$(learned_macs)"
echo "  MACs learned on the access port: $ATTACK_COUNT ($(learned_list))"
echo

if [[ "$BASE_COUNT" == "1" && "$SENT" == "3" && "$ATTACK_COUNT" == "3" ]]; then
    echo "Result: with only the authorized device, the access port learned one MAC. Behind a mini-switch it learned three on the same port. A port that allows one MAC would be violated, but the Linux bridge enforces no limit, so the violation action is not reproduced here. Test it on the target switch."
    exit 0
elif [[ "$BASE_COUNT" == "0" || "$ATTACK_COUNT" == "0" ]]; then
    echo "Result: inconclusive. The bridge did not learn the client MACs on the access port. Result unreliable."
    exit 2
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
