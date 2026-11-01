#!/usr/bin/env bash
# Isolated VLAN hopping lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   attacker --(veth)-- [switch: br0, port sw-a] --(veth)-- [port sw-m] monitor
#
#   Phase 1: the attacker's port behaves as an access port. Tagged probes are
#   dropped at ingress, so the monitor receives none.
#   Phase 2: the port carries VLAN 20 tagged, as a trunk does after a successful
#   negotiation. The probes tagged with VLAN 20 are forwarded to the monitor.
#
# Port VLAN membership is emulated with an nftables bridge rule, because the kernel
# used for the labs has no VLAN-filtering bridges. The rule plays the role of the
# switch's port configuration; it is not a switch behavior being tested.
#
# What this lab proves: a port that does not carry the target VLAN drops tagged
# frames for it, and a port that carries it forwards them. It does not prove that
# DTP creates the trunk. That is the job of the switch spoofing lab, and it needs a
# switch with DTP enabled. The phase 2 rule is a simulated outcome.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/vlan_hopping_lab.sh
#   sudo FRAMES=20 scripts/lab/vlan_hopping_lab.sh
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

# Phase 1 port configuration: access port, so tagged frames are dropped on ingress.
ip netns exec switch nft -f - <<NFT
table bridge vlanhop {
    chain input {
        type filter hook prerouting priority -300; policy accept;
        iifname "sw-a" ether type 0x8100 drop
    }
}
NFT

# Counts tagged frames from the attacker with VLAN ID 20 that reach the monitor.
SNIFFER_CODE='
import os
from scapy.all import sniff
ATTACKER = bytes.fromhex(os.environ["ATTACKER_MAC"].replace(":", ""))
count = 0
def cb(pkt):
    global count
    raw = bytes(pkt)
    if len(raw) >= 16 and raw[6:12] == ATTACKER and raw[12:14] == b"\x81\x00":
        if int.from_bytes(raw[14:16], "big") & 0x0FFF == 20:
            count += 1
sniff(iface="m-sw", prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(f"{count}\n")
'

SEND_CODE='
import os, threading
from macabre.attacks.vlan_hopping import VlanHoppingConfig, run_vlan_hopping
stats = run_vlan_hopping(
    VlanHoppingConfig(iface="a-sw", target_vlan=20, negotiate=False,
                      count=int(os.environ["FRAMES"]), interval=0.1),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} probes tagged with VLAN 20")
'

# --- Phase 1: access port -------------------------------------------------

echo "Phase 1: attacker's port is an access port; probes tagged with VLAN 20"
ip netns exec monitor env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$WORK/phase1" "$PY" -c "$SNIFFER_CODE" &
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" FRAMES="$FRAMES" "$PY" -c "$SEND_CODE"
wait $!
echo "  VLAN 20 probes reaching the monitor: $(cat "$WORK/phase1") of $FRAMES"
echo

# --- Phase 2: port carries VLAN 20 tagged (simulated trunk outcome) -------

echo "Phase 2: the port carries VLAN 20 tagged (simulated trunk outcome)"
ip netns exec switch nft flush chain bridge vlanhop input
ip netns exec switch nft add rule bridge vlanhop input iifname "sw-a" vlan id != 20 drop
ip netns exec monitor env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
    SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$WORK/phase2" "$PY" -c "$SNIFFER_CODE" &
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" FRAMES="$FRAMES" "$PY" -c "$SEND_CODE"
wait $!
echo "  VLAN 20 probes reaching the monitor: $(cat "$WORK/phase2") of $FRAMES"
echo
echo "Expected: phase 1 drops every tagged probe at ingress, so the monitor receives none."
echo "Phase 2 forwards the VLAN 20 probes. Whether DTP creates that trunk is tested separately."
