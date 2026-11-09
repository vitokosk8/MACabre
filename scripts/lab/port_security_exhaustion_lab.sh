#!/usr/bin/env bash
# Isolated port security exhaustion lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   victim   --(veth)-- [switch: bridge br0, port p-vic]
#   attacker --(veth)-- [switch: bridge br0, port p-att]
#
#   switch:   a Linux bridge. It learns each source MAC on the port it arrives on.
#   attacker: MACabre's port security exhaustion sender, on p-att.
#   victim:   a legitimate host on its own port, sending one frame so the switch learns it.
#
#   Phase 0 (baseline): the victim sends one frame. The switch learns the victim's MAC on p-vic.
#                       The attacker's port has no learned addresses.
#   Phase 1 (exhaustion): the attacker sends FRAMES frames, each with a new source MAC.
#                       Checked: how many distinct addresses the switch learns on p-att, and
#                       whether the victim's entry stays on p-vic.
#
# What this shows: the sender produces one new learned address per frame on its port, and the
# legitimate host's entry on its own port is kept. This is what the attacker controls.
#
# What it does not show: a Linux bridge has no per-port MAC limit, so no violation action is
# triggered here. Whether a switch shuts down, restricts, or drops the legitimate host once
# the limit is reached needs a real switch with port security configured.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/port_security_exhaustion_lab.sh
#   sudo FRAMES=40 scripts/lab/port_security_exhaustion_lab.sh
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
FRAMES="${FRAMES:-20}"
ATTACKER_MAC="02:00:00:00:00:30"
VICTIM_MAC="02:00:00:00:00:50"
WORK="$(mktemp -d)"
chmod 755 "$WORK"

stop_lab() {
    for ns in attacker victim switch; do
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
ip netns add attacker

for pair in "vic:victim:$VICTIM_MAC" "att:attacker:$ATTACKER_MAC"; do
    name="$(echo "$pair" | cut -d: -f1)"
    ns="$(echo "$pair" | cut -d: -f2)"
    mac="$(echo "$pair" | cut -d: -f3-)"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns switch
    ip netns exec "$ns" ip link set "h-$name" address "$mac"
    ip netns exec "$ns" ip link set "h-$name" up
    ip netns exec switch ip link set "p-$name" up
done

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for name in vic att; do
    ip netns exec switch ip link set "p-$name" master br0
done

# Sends one frame from the victim's MAC, so the switch learns it on p-vic.
VICTIM_CODE='
import os
from scapy.all import Ether, Raw, sendp
sendp(Ether(src=os.environ["SOURCE_MAC"], dst="ff:ff:ff:ff:ff:ff", type=0x88B5) / Raw(b"victim"), iface="h-vic", verbose=False)
'

# Sends FRAMES frames from the attacker, each with a new source MAC.
SEND_CODE='
import os, random, threading
from macabre.attacks.port_security_exhaustion import PortSecurityExhaustionConfig, run_port_security_exhaustion
run_port_security_exhaustion(
    PortSecurityExhaustionConfig(iface="h-att", rate=50, count=int(os.environ["FRAMES"])),
    threading.Event(),
    lambda _s: None,
    rng=random.Random(),
)
'

# Number of learned (non-permanent) addresses on a bridge port.
learned_on() {
    ip netns exec switch bridge fdb show br br0 | awk -v p="$1" '$2 == "dev" && $3 == p && !/permanent/' | wc -l
}

# The port the victim's MAC is learned on, or "none".
victim_port() {
    ip netns exec switch bridge fdb show br br0 | awk -v m="$VICTIM_MAC" '$1 == m {print $3; exit}' | grep . || echo none
}

echo "Phase 0: baseline, the victim sends one frame"
ip netns exec victim env PYTHONPATH="$ROOT/src" SOURCE_MAC="$VICTIM_MAC" \
    "$PY" -c "$VICTIM_CODE" >/dev/null 2>&1
sleep 1
BASE_LEARNED="$(learned_on p-att)"
BASE_VICTIM="$(victim_port)"
echo "  addresses learned on the attacker's port: $BASE_LEARNED"
echo "  switch entry for the victim's MAC: $BASE_VICTIM"
echo

echo "Phase 1: exhaustion, the attacker sends $FRAMES frames, each with a new source MAC"
ip netns exec attacker env PYTHONPATH="$ROOT/src" FRAMES="$FRAMES" \
    "$PY" -c "$SEND_CODE" >/dev/null 2>&1
sleep 1
LEARNED="$(learned_on p-att)"
VICTIM_AFTER="$(victim_port)"
echo "  addresses learned on the attacker's port: $LEARNED"
echo "  switch entry for the victim's MAC after the flood: $VICTIM_AFTER"
echo

# The attacker's port already holds its own address from the attacker's IPv6 traffic before the flood, so
# the verdict counts the addresses the flood adds, not the total.
NEW_LEARNED=$((LEARNED - BASE_LEARNED))
echo "  addresses added by the flood: $NEW_LEARNED"
echo

if [[ "$BASE_VICTIM" == "p-vic" && "$NEW_LEARNED" == "$FRAMES" && "$VICTIM_AFTER" == "p-vic" ]]; then
    echo "Result: the attacker's port learned $NEW_LEARNED distinct addresses from $FRAMES frames, and the legitimate host's entry on its own port was kept. The Linux bridge has no per-port MAC limit, so no violation action was triggered. Port security behavior needs a real switch."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
