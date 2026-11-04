#!/usr/bin/env bash
# Isolated DHCP relay option 82 lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with two hosts attached:
#
#   server:   dnsmasq (10.99.0.1). It has two pools: a default pool (10.99.0.100-119) and
#             a pool selected by circuit ID "pool-a" in Option 82 (10.99.0.150-159).
#   attacker: MACabre's relay option 82 sender, and a sniffer that reads the OFFER for
#             the client MAC.
#
#   Phase 1 (baseline): a DISCOVER without Option 82. The offer comes from the default pool.
#   Phase 2 (forged): a DISCOVER with the forged circuit ID "pool-a". The offer comes from
#                     the pool selected for that circuit.
#
# What this shows: whether the server picks the pool from the Option 82 circuit ID the
# client sent. A relay that replaces client-supplied Option 82 is not in the lab; its
# behavior needs the target device.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcp_relay_option82_lab.sh
#
# Requirements: iproute2, dnsmasq, and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip dnsmasq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
CLIENT_MAC="02:00:00:00:00:60"
WORK="$(mktemp -d)"

stop_lab() {
    for pid in $(ip netns pids server 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    for ns in server attacker lan; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

stop_lab

ip netns add lan
ip netns add server
ip netns add attacker

for pair in "srv:server" "att:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in srv att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec server ip link set lo up
ip netns exec server ip addr add 10.99.0.1/24 dev h-srv
ip netns exec server ip link set h-srv up
ip netns exec attacker ip link set h-att up

ip netns exec server dnsmasq \
    --keep-in-foreground \
    --interface=h-srv \
    --bind-interfaces \
    --port=0 \
    --conf-file=/dev/null \
    --dhcp-authoritative \
    --no-ping \
    --dhcp-circuitid=set:pool-a,pool-a \
    --dhcp-range=10.99.0.100,10.99.0.119,12h \
    --dhcp-range=tag:pool-a,10.99.0.150,10.99.0.159,12h \
    --dhcp-leasefile="$WORK/leases" &
sleep 2

# Sends one DISCOVER: without Option 82 when CIRCUIT is empty, otherwise with MACabre's module.
SEND_CODE='
import os, threading
circuit = os.environ.get("CIRCUIT", "")
if circuit:
    from macabre.attacks.dhcp_relay_option82 import RelayOption82Config, run_relay_option82
    run_relay_option82(
        RelayOption82Config(iface="h-att", circuit_id=circuit, client_mac=os.environ["CLIENT_MAC"]),
        threading.Event(),
        lambda _s: None,
    )
else:
    from scapy.all import sendp
    from macabre.attacks.dhcp_starvation import build_discover
    import random
    sendp(build_discover(os.environ["CLIENT_MAC"], random.getrandbits(32)), iface="h-att", verbose=False)
'

# Prints the address of the first OFFER for the client MAC, or "none".
OBSERVE_CODE='
import os, time
from scapy.all import AsyncSniffer, BOOTP, DHCP
MAC = os.environ["CLIENT_MAC"]
bytes_mac = bytes.fromhex(MAC.replace(":", "")).ljust(16, b"\x00")
offers = []
def on(p):
    if p.haslayer(DHCP) and p.haslayer(BOOTP) and p[BOOTP].op == 2 and p[BOOTP].chaddr == bytes_mac:
        if any(o == ("message-type", 2) for o in p[DHCP].options if isinstance(o, tuple)):
            offers.append(p[BOOTP].yiaddr)
s = AsyncSniffer(iface="h-att", store=False, prn=on)
s.start()
time.sleep(3)
s.stop()
print(offers[0] if offers else "none")
'

offer_for() {
    local circuit="$1" out="$WORK/offer.txt"
    ip netns exec attacker env PYTHONPATH="$ROOT/src" CLIENT_MAC="$CLIENT_MAC" "$PY" -c "$OBSERVE_CODE" > "$out" &
    local obs=$!
    sleep 1
    ip netns exec attacker env PYTHONPATH="$ROOT/src" CLIENT_MAC="$CLIENT_MAC" CIRCUIT="$circuit" \
        "$PY" -c "$SEND_CODE" >/dev/null 2>&1
    wait "$obs" || true
    tail -1 "$out"
}

echo "Phase 1: baseline, DISCOVER without Option 82"
BASE="$(offer_for "")"
echo "  address offered: $BASE"
echo

echo "Phase 2: forged, DISCOVER with circuit ID pool-a"
FORGED="$(offer_for "pool-a")"
echo "  address offered: $FORGED"
echo

if [[ "$BASE" == 10.99.0.1[0-1][0-9] && "$FORGED" == 10.99.0.15[0-9] ]]; then
    echo "Result: without Option 82 the server offered $BASE from its default pool. With circuit ID pool-a it offered $FORGED from the pool for that circuit, so the client chose its pool. Relays that replace client-supplied Option 82 need the target device."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
