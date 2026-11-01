#!/usr/bin/env bash
# Isolated MAB bypass lab (Linux only, needs root and nft).
#
# Topology, all inside network namespaces:
#
#   attacker --(veth)-- [switch: bridge br0, port p-att] ... [port p-gw] --(veth)-- gateway
#
#   switch:   a bridge with a MAC allow list on the attacker's port. A bridge-family nftables
#             rule drops frames from the port unless their source MAC is the allowed device.
#             This stands in for MAC-based authentication (MAB) on a switch port.
#   gateway:  a host at 10.99.0.1 that answers ARP requests for its address.
#   attacker: MACabre's MAB bypass audit. It probes the gateway from a chosen MAC and restores
#             its own MAC afterwards.
#
#   Phase 1: the attacker probes with its own MAC. The allow list drops the frame, so no reply.
#   Phase 2: the attacker clones the allowed device's MAC and probes again. The port
#            forwards the probe and the gateway replies.
#
# This models a MAC allow list only. Real MAB runs through RADIUS and 802.1X, which this lab
# does not implement. The lab checks that the attacker's MAC is restored after each phase.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/mab_bypass_lab.sh
#
# Requirements: iproute2, nft (nftables), and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip nft; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
ATTACKER_MAC="02:00:00:00:00:30"
ALLOWED_MAC="02:00:00:00:00:50"
GATEWAY_IP="10.99.0.1"

stop_lab() {
    for ns in attacker gateway switch; do
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
ip netns add gateway
ip netns add attacker

ip link add a-sw type veth peer name p-att
ip link set a-sw netns attacker
ip link set p-att netns switch

ip link add g-sw type veth peer name p-gw
ip link set g-sw netns gateway
ip link set p-gw netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in p-att p-gw; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec attacker ip link set a-sw address "$ATTACKER_MAC"
ip netns exec attacker ip link set a-sw up
ip netns exec gateway ip link set g-sw up
ip netns exec gateway ip addr add "$GATEWAY_IP/24" dev g-sw

# MAC allow list on the attacker's port: only the allowed device's source MAC may pass.
ip netns exec switch nft add table bridge macauth
ip netns exec switch nft add chain bridge macauth forward '{ type filter hook prerouting priority 0 ; }'
ip netns exec switch nft add rule bridge macauth forward iifname "p-att" ether saddr != "$ALLOWED_MAC" drop

# The gateway's ARP table is not needed: it answers requests for its own address.
PROBE_CODE='
import os, threading
from macabre.attacks.mab_bypass import MabBypassConfig, run_mab_bypass
stats = run_mab_bypass(
    MabBypassConfig(iface="a-sw", target_mac=os.environ["TARGET_MAC"],
                    gateway_ip=os.environ["GATEWAY_IP"], wait_seconds=2.0),
    threading.Event(),
    lambda _s: None,
)
print(f"Audit: probe sent {stats.probes}, reply {stats.reply}, original MAC {stats.original_mac}")
print(f"Audit: {stats.status}")
'

run_phase() {
    local label="$1" target="$2"
    echo "Phase: $label (probe with $target)"
    ip netns exec attacker env PYTHONPATH="$ROOT/src" TARGET_MAC="$target" GATEWAY_IP="$GATEWAY_IP" \
        "$PY" -c "$PROBE_CODE" > "$WORK/$label.txt" 2>"$WORK/$label.err" || true
    cat "$WORK/$label.txt"
    local now
    now="$(ip netns exec attacker cat /sys/class/net/a-sw/address)"
    if [[ "$now" == "$ATTACKER_MAC" ]]; then
        echo "Check: attacker MAC restored to $ATTACKER_MAC"
    else
        echo "Check: attacker MAC is $now, not restored"
    fi
    echo
}

run_phase "own-mac" "$ATTACKER_MAC"
run_phase "cloned-mac" "$ALLOWED_MAC"

FINAL_MAC="$(ip netns exec attacker cat /sys/class/net/a-sw/address)"
if grep -q "did not accept" "$WORK/own-mac.txt" && grep -q "forwarded the probe" "$WORK/cloned-mac.txt" \
    && [[ "$FINAL_MAC" == "$ATTACKER_MAC" ]]; then
    echo "Result: the port refused the attacker's own MAC and forwarded the probe sent with the allowed MAC. The attacker's MAC was restored. This models a MAC allow list, not RADIUS or 802.1X."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable. See $WORK for the phase output."
    exit 1
fi
