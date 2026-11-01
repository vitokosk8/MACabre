#!/usr/bin/env bash
# Isolated switch spoofing (DTP) lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   attacker --(veth)-- [switch: br0, port sw-a] --(veth)-- monitor (sw-m port)
#
#   Phase 1 (baseline): nothing is sent, and the monitor sees no DTP frames.
#   Phase 2: the attacker sends DTP trunk advertisements to 01:00:0c:cc:cc:cc.
#   The monitor, on another switch port, captures them and checks their structure.
#
# What this lab proves: the frames are built correctly and reach a switch port.
# A Linux bridge does not run DTP and does not form trunks, so this lab cannot
# show that a switch negotiates a trunk. Test that on a switch with DTP enabled.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/switch_spoofing_lab.sh
#   sudo FRAMES=20 scripts/lab/switch_spoofing_lab.sh
#
# Requirements: iproute2 (ip, bridge), and the project virtualenv (.venv).
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
FRAMES="${FRAMES:-10}"
SNIFF_SECONDS=6
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

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
ip netns add attacker
ip netns add monitor

# attacker <-> switch port sw-a
ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

# monitor <-> switch port sw-m
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

# Captures DTP frames on the monitor port and reports how many are well formed.
SNIFFER_CODE='
import os
from scapy.all import sniff
DTP_DST = bytes.fromhex("01000ccccccc")
SNAP = bytes.fromhex("aaaa03" "00000c" "2004")
ATTACKER = bytes.fromhex(os.environ["ATTACKER_MAC"].replace(":", ""))
count = 0
bad = 0
def cb(pkt):
    # Frames with an 802.3 length are dissected as LLC, so read the raw bytes.
    global count, bad
    raw = bytes(pkt)
    if raw[0:6] == DTP_DST and raw[14:22] == SNAP:
        count += 1
        if raw[6:12] != ATTACKER or raw[22] != 0x01:
            bad += 1
sniff(iface="m-sw", prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(f"{count} {bad}")
'

SEND_CODE='
import os
from macabre.attacks.switch_spoofing import SwitchSpoofingConfig, run_switch_spoofing
import threading
stats = run_switch_spoofing(
    SwitchSpoofingConfig(iface="a-sw", count=int(os.environ["FRAMES"]), interval=0.1),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} DTP frames from {stats.sender_mac}")
'

# --- Phase 1: baseline -----------------------------------------------------

echo "Phase 1: nothing is sent yet"
ip netns exec monitor env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    SNIFF_SECONDS=2 OUT="$WORK/baseline" "$PY" -c "$SNIFFER_CODE"
echo "  DTP frames seen by the monitor: $(cut -d' ' -f1 "$WORK/baseline")"
echo

# --- Phase 2: DTP trunk advertisements -------------------------------------

echo "Phase 2: attacker sends $FRAMES DTP trunk advertisements"
ip netns exec monitor env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$WORK/attack" "$PY" -c "$SNIFFER_CODE" &
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" FRAMES="$FRAMES" "$PY" -c "$SEND_CODE"
wait

read -r seen bad <<< "$(cat "$WORK/attack")"
echo "  DTP frames seen by the monitor: $seen of $FRAMES ($bad malformed)"
echo
echo "Expected: the monitor sees every frame, all with the DTP multicast address, the"
echo "LLC/SNAP header and the attacker's source MAC. The switch's trunk decision is not"
echo "tested here; it needs a switch with DTP enabled."
