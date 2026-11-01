#!/usr/bin/env bash
# Isolated native VLAN abuse lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   attacker --(veth)-- [switch: br0, port sw-a] --(veth)-- [port sw-m] monitor
#
# The attacker sends untagged probes, which is native-VLAN traffic on its port, and
# the monitor checks that they arrive untagged on the other side of the switch.
#
# What this lab proves: the probes the attack sends carry no VLAN tag, and they reach
# a switch port in that form. It does NOT test the abuse itself. The abuse happens when
# the two ends of a trunk disagree about the native VLAN: the far end then places the
# untagged probes in its own native VLAN. Reproducing that needs a switch-side VLAN
# action, which the kernel used for the labs does not provide (no VLAN-filtering
# bridges, no vlan push action). Test the mismatch on two real switches.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/native_vlan_lab.sh
#   sudo FRAMES=20 scripts/lab/native_vlan_lab.sh
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

# Counts the probes from the attacker that reach the monitor, untagged and tagged.
SNIFFER_CODE='
import os
from scapy.all import sniff
ATTACKER = bytes.fromhex(os.environ["ATTACKER_MAC"].replace(":", ""))
untagged = 0
tagged = 0
def cb(pkt):
    global untagged, tagged
    raw = bytes(pkt)
    if len(raw) >= 14 and raw[6:12] == ATTACKER:
        if raw[12:14] == b"\x81\x00":
            tagged += 1
        elif raw[12:14] == b"\x08\x06":
            untagged += 1
sniff(iface="m-sw", prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(f"{untagged} {tagged}\n")
'

SEND_CODE='
import os, threading
from macabre.attacks.native_vlan_abuse import NativeVlanConfig, run_native_vlan_abuse
stats = run_native_vlan_abuse(
    NativeVlanConfig(iface="a-sw", count=int(os.environ["FRAMES"]), interval=0.1),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} untagged probes")
'

echo "Sending untagged probes from the attacker's native VLAN port"
ip netns exec monitor env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$WORK/run" "$PY" -c "$SNIFFER_CODE" &
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" FRAMES="$FRAMES" "$PY" -c "$SEND_CODE"
wait $!
read -r untagged tagged <<< "$(cat "$WORK/run")"
echo "  monitor received untagged: $untagged, tagged: $tagged (of $FRAMES sent)"
echo
echo "Expected: every probe arrives untagged. The VLAN change happens only when the far end"
echo "treats the untagged frames as its own native VLAN, which needs two real switches."
