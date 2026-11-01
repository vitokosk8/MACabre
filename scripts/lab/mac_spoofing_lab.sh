#!/usr/bin/env bash
# Isolated MAC address spoofing lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   sender   --(veth)-- [switch: br0] --(veth)-- target    (MAC TARGET_MAC)
#                             |
#                             +--(veth)-- attacker
#
#   Phase 1 (baseline): the target sends one frame, so the switch learns
#   TARGET_MAC on the target's port. The sender's frames reach the target only.
#   Phase 2 (spoofing): the attacker sends frames with source TARGET_MAC. The
#   switch moves the TARGET_MAC entry to the attacker's port, and the sender's
#   frames now reach the attacker only.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/mac_spoofing_lab.sh
#   sudo FRAMES=100 SPOOF_FRAMES=10 scripts/lab/mac_spoofing_lab.sh
#
# Requirements: iproute2 (ip, bridge), and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-20}"
SPOOF_FRAMES="${SPOOF_FRAMES:-5}"
SNIFF_SECONDS=8
TARGET_MAC="02:00:00:00:00:10"
SENDER_MAC="02:00:00:00:00:01"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in target sender attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
ip netns add sender
ip netns add target
ip netns add attacker

# sender <-> switch port sw-s
ip link add s-sw type veth peer name sw-s
ip link set s-sw netns sender
ip link set sw-s netns switch

# target <-> switch port sw-t
ip link add t-sw type veth peer name sw-t
ip link set t-sw netns target
ip link set sw-t netns switch

# attacker <-> switch port sw-a
ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-s sw-t sw-a; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec sender ip link set s-sw address "$SENDER_MAC"
ip netns exec sender ip link set s-sw up
ip netns exec target ip link set t-sw address "$TARGET_MAC"
ip netns exec target ip link set t-sw up
ip netns exec attacker ip link set a-sw up

# Port of the switch where the bridge currently has TARGET_MAC (empty if unknown).
port_of_target() {
    ip netns exec switch bridge fdb show br br0 \
        | grep -i "$TARGET_MAC" | grep -v permanent \
        | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}' \
        | head -n 1
}

# Start a background sniffer that counts unicast frames addressed to TARGET_MAC
# with EtherType 0x88B5, for SNIFF_SECONDS. The count is written to $out.
start_sniffer() {
    local ns="$1" iface="$2" out="$3"
    ip netns exec "$ns" env PYTHONPATH="$ROOT/src" TARGET_MAC="$TARGET_MAC" \
        SNIFF_SECONDS="$SNIFF_SECONDS" IFACE="$iface" OUT="$out" "$PY" -c "$SNIFFER_CODE" &
}

SNIFFER_CODE='
import os
from scapy.all import Ether, sniff
target = os.environ["TARGET_MAC"]
count = 0
def cb(pkt):
    global count
    if Ether in pkt and pkt[Ether].dst == target and pkt[Ether].type == 0x88B5:
        count += 1
sniff(iface=os.environ["IFACE"], prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(str(count))
'

# Send $COUNT frames with the given source and destination MAC from $iface.
send_frames() {
    local ns="$1" iface="$2" src="$3" dst="$4" count="$5"
    ip netns exec "$ns" env PYTHONPATH="$ROOT/src" IFACE="$iface" SRC="$src" DST="$dst" \
        COUNT="$count" "$PY" -c "$SENDER_CODE"
}

SENDER_CODE='
import os
from scapy.all import Ether, Raw, sendp
sendp(
    Ether(src=os.environ["SRC"], dst=os.environ["DST"], type=0x88B5) / Raw(b"x" * 46),
    iface=os.environ["IFACE"],
    count=int(os.environ["COUNT"]),
    verbose=False,
)
'

SPOOF_CODE='
import os, threading
from macabre.attacks.mac_spoofing import MacSpoofingConfig, run_spoofing
stats = run_spoofing(
    MacSpoofingConfig(
        iface=os.environ["IFACE"],
        target_mac=os.environ["TARGET_MAC"],
        count=int(os.environ["COUNT"]),
    ),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: spoofed frames sent {stats.frames}")
'

# --- Phase 1: baseline -----------------------------------------------------

echo "Phase 1: baseline, $FRAMES frames from the sender to $TARGET_MAC"
start_sniffer target t-sw "$WORK/target_1"
start_sniffer attacker a-sw "$WORK/attacker_1"
sleep 2

# The target speaks once so the switch learns its MAC on port sw-t.
send_frames target t-sw "$TARGET_MAC" ff:ff:ff:ff:ff:ff 1
sleep 1
send_frames sender s-sw "$SENDER_MAC" "$TARGET_MAC" "$FRAMES"

wait
echo "  switch port for $TARGET_MAC:   $(port_of_target)"
echo "  received by target:            $(cat "$WORK/target_1") of $FRAMES"
echo "  received by attacker:          $(cat "$WORK/attacker_1") of $FRAMES"
echo

# --- Phase 2: spoofing -----------------------------------------------------

echo "Phase 2: attacker spoofs $TARGET_MAC with $SPOOF_FRAMES frames, then the sender sends $FRAMES more"
start_sniffer target t-sw "$WORK/target_2"
start_sniffer attacker a-sw "$WORK/attacker_2"
sleep 2

ip netns exec attacker env PYTHONPATH="$ROOT/src" TARGET_MAC="$TARGET_MAC" \
    IFACE=a-sw COUNT="$SPOOF_FRAMES" "$PY" -c "$SPOOF_CODE"
sleep 1
send_frames sender s-sw "$SENDER_MAC" "$TARGET_MAC" "$FRAMES"

wait
echo "  switch port for $TARGET_MAC:   $(port_of_target)"
echo "  received by target:            $(cat "$WORK/target_2") of $FRAMES"
echo "  received by attacker:          $(cat "$WORK/attacker_2") of $FRAMES"
echo
echo "Expected: in phase 1 the target receives the frames; in phase 2 the switch"
echo "moves $TARGET_MAC to the attacker port, and the attacker receives them."
