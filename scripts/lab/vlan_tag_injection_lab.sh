#!/usr/bin/env bash
# Isolated VLAN tag injection lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   attacker --(veth)-- [switch: br0, port sw-a] --(veth)-- [port sw-m] monitor
#
#   The attacker sends tagged probes: VLAN 20, priority (PCP) 5, DEI 0.
#
#   Phase 1: the attacker's port behaves as an access port. Injected tags are dropped
#   at ingress, so the monitor receives none.
#   Phase 2: the port accepts the injected tags and forwards them. The monitor checks
#   that the VLAN ID and the priority arrive unchanged.
#
# Port behavior is emulated with an nftables bridge rule, because the kernel used for
# the labs has no VLAN-filtering bridges. Phase 2 is a simulated outcome: a real switch
# decides whether it accepts an injected tag, and whether it keeps the priority. The lab
# checks that the frames keep their fields when a port passes them.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/vlan_tag_injection_lab.sh
#   sudo FRAMES=20 scripts/lab/vlan_tag_injection_lab.sh
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
VLAN=20
PCP=5
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

# Counts injected-tag frames from the attacker that reach the monitor, and whether their
# VLAN ID and priority are unchanged.
SNIFFER_CODE='
import os
from scapy.all import sniff
ATTACKER = bytes.fromhex(os.environ["ATTACKER_MAC"].replace(":", ""))
count = 0
intact = 0
def cb(pkt):
    global count, intact
    raw = bytes(pkt)
    if len(raw) >= 16 and raw[6:12] == ATTACKER and raw[12:14] == b"\x81\x00":
        tci = int.from_bytes(raw[14:16], "big")
        count += 1
        if tci & 0x0FFF == int(os.environ["VLAN"]) and (tci >> 13) == int(os.environ["PCP"]):
            intact += 1
sniff(iface="m-sw", prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(f"{count} {intact}\n")
'

SEND_CODE='
import os, threading
from macabre.attacks.vlan_tag_injection import VlanTagInjectionConfig, run_vlan_tag_injection
stats = run_vlan_tag_injection(
    VlanTagInjectionConfig(iface="a-sw", vlan=int(os.environ["VLAN"]), pcp=int(os.environ["PCP"]),
                           count=int(os.environ["FRAMES"]), interval=0.1),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} injected-tag frames")
'

run_phase() {
    local out="$1"
    ip netns exec monitor env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
        VLAN="$VLAN" PCP="$PCP" SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$out" "$PY" -c "$SNIFFER_CODE" &
    sleep 2
    ip netns exec attacker env PYTHONPATH="$ROOT/src" VLAN="$VLAN" PCP="$PCP" FRAMES="$FRAMES" "$PY" -c "$SEND_CODE"
    wait $!
}

# --- Phase 1: access port drops injected tags -----------------------------

echo "Phase 1: access port; injected tags VLAN $VLAN, PCP $PCP"
ip netns exec switch nft -f - <<NFT
table bridge injlab {
    chain input {
        type filter hook prerouting priority -300; policy accept;
        iifname "sw-a" ether type 0x8100 drop
    }
}
NFT
run_phase "$WORK/phase1"
read -r count1 intact1 <<< "$(cat "$WORK/phase1")"
echo "  injected-tag frames reaching the monitor: $count1 of $FRAMES"
echo

# --- Phase 2: port passes injected tags -----------------------------------

echo "Phase 2: the port passes injected tags (simulated switch decision)"
ip netns exec switch nft flush chain bridge injlab input
run_phase "$WORK/phase2"
read -r count2 intact2 <<< "$(cat "$WORK/phase2")"
echo "  injected-tag frames reaching the monitor: $count2 of $FRAMES (VLAN and PCP unchanged: $intact2)"
echo
echo "Expected: phase 1 drops every injected tag. Phase 2 delivers them with the VLAN ID and"
echo "priority the attacker chose. Whether a real switch accepts or rewrites them is tested on that switch."
