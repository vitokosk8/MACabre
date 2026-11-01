#!/usr/bin/env bash
# Isolated double-tagging lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   attacker --(veth)-- [switch: br0, port sw-a] --(veth)-- [port sw-m] monitor
#
#   Frames sent: outer tag VLAN 10 (the native VLAN), inner tag VLAN 20 (the target).
#
#   Phase 1: the attacker's port behaves as an access port. Tagged frames are dropped
#   at ingress, so the monitor receives none.
#   Phase 2: the port passes the frames. The monitor receives them with both tags,
#   in the order they were sent.
#
# What this lab proves: the double-tagged frame is built correctly, and an access
# port drops it while a port that passes tags forwards it intact. It does not prove
# that a switch removes the outer tag and moves the frame into VLAN 20. Real switches
# strip the outer tag only when it matches their native VLAN, and this lab bridge does
# not strip tags at all. That step needs a switch, and it is not tested here.
#
# Port behavior is emulated with an nftables bridge rule, because the kernel used for
# the labs has no VLAN-filtering bridges.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/double_tagging_lab.sh
#   sudo FRAMES=20 scripts/lab/double_tagging_lab.sh
#
# Requirements: iproute2 (ip, bridge), nft (nftables), and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge nft; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-10}"
SNIFF_SECONDS=6
NATIVE_VLAN=10
TARGET_VLAN=20
ATTACKER_MAC="02:00:00:00:00:30"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in monitor attacker switch; do
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
ip netns add attacker
ip netns add monitor

ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

ip link add m-sw type veth peer name sw-m
ip link set m-sw netns monitor
ip link set sw-m netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-a sw-m; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec attacker ip link set a-sw address "$ATTACKER_MAC"
ip netns exec attacker ip link set a-sw up
ip netns exec monitor ip link set m-sw up

# Phase 1 port configuration: access port, tagged frames dropped on ingress.
ip netns exec switch nft -f - <<NFT
table bridge dtlab {
    chain input {
        type filter hook prerouting priority -300; policy accept;
        iifname "sw-a" ether type 0x8100 drop
    }
}
NFT

# Reports the tags of frames from the attacker that reach the monitor.
SNIFFER_CODE='
import os
from scapy.all import sniff
ATTACKER = bytes.fromhex(os.environ["ATTACKER_MAC"].replace(":", ""))
count = 0
double = 0
def cb(pkt):
    global count, double
    raw = bytes(pkt)
    if len(raw) >= 20 and raw[6:12] == ATTACKER and raw[12:14] == b"\x81\x00" and raw[16:18] == b"\x81\x00":
        count += 1
        outer = int.from_bytes(raw[14:16], "big") & 0x0FFF
        inner = int.from_bytes(raw[18:20], "big") & 0x0FFF
        if outer == int(os.environ["NATIVE_VLAN"]) and inner == int(os.environ["TARGET_VLAN"]):
            double += 1
sniff(iface="m-sw", prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(f"{count} {double}\n")
'

SEND_CODE='
import os, threading
from macabre.attacks.double_tagging import DoubleTaggingConfig, run_double_tagging
stats = run_double_tagging(
    DoubleTaggingConfig(iface="a-sw", native_vlan=int(os.environ["NATIVE_VLAN"]),
                        target_vlan=int(os.environ["TARGET_VLAN"]),
                        count=int(os.environ["FRAMES"]), interval=0.1),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} double-tagged probes")
'

# --- Phase 1: access port -------------------------------------------------

echo "Phase 1: access port; probes tagged $NATIVE_VLAN (outer) and $TARGET_VLAN (inner)"
ip netns exec monitor env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    NATIVE_VLAN="$NATIVE_VLAN" TARGET_VLAN="$TARGET_VLAN" \
    SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$WORK/phase1" "$PY" -c "$SNIFFER_CODE" &
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" NATIVE_VLAN="$NATIVE_VLAN" \
    TARGET_VLAN="$TARGET_VLAN" FRAMES="$FRAMES" "$PY" -c "$SEND_CODE"
wait $!
read -r seen1 double1 <<< "$(cat "$WORK/phase1")"
echo "  frames reaching the monitor: $seen1 of $FRAMES (with both tags: $double1)"
echo

# --- Phase 2: port passes tagged frames ----------------------------------

echo "Phase 2: the port passes tagged frames"
ip netns exec switch nft flush chain bridge dtlab input
ip netns exec monitor env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    NATIVE_VLAN="$NATIVE_VLAN" TARGET_VLAN="$TARGET_VLAN" \
    SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$WORK/phase2" "$PY" -c "$SNIFFER_CODE" &
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" NATIVE_VLAN="$NATIVE_VLAN" \
    TARGET_VLAN="$TARGET_VLAN" FRAMES="$FRAMES" "$PY" -c "$SEND_CODE"
wait $!
read -r seen2 double2 <<< "$(cat "$WORK/phase2")"
echo "  frames reaching the monitor: $seen2 of $FRAMES (with both tags: $double2)"
echo
echo "Expected: phase 1 drops every tagged frame. Phase 2 delivers them with both tags intact."
echo "The switch step, where the outer tag is removed and the frame enters VLAN $TARGET_VLAN,"
echo "is a switch behavior. It is not tested by this lab."
