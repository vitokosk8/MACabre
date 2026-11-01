#!/usr/bin/env bash
# Isolated DHCP offer flooding lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the legitimate DHCP server (10.99.0.1, pool 10.99.0.100-119).
#   attacker: MACabre's offer flood. It answers each DISCOVER with 10 offers from invented
#             servers in 10.99.0.128/25, with random addresses and gateways.
#   client:   a DHCP client that sends DISCOVERs and records every offer that matches its
#             transaction ID, in arrival order.
#
#   Phase 1 (baseline): only the legitimate server runs. Each round has one offer.
#   Phase 2 (race): the legitimate server and the flood both run. Each round has up to 11
#            offers, and the lab records whether the first one came from the flood.
#   Phase 3 (alone): the legitimate server is stopped. The client's first offer should come
#            from the flood, from an invented server.
#
# The lab counts offers and first arrivals. It does not measure the client's processing
# cost, so the overload effect of the flood is not measured here.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcp_offer_flooding_lab.sh
#   sudo ROUNDS=10 scripts/lab/dhcp_offer_flooding_lab.sh
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
LEGIT_IP="10.99.0.1"
WORK="$(mktemp -d)"

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
    --log-facility="$WORK/dnsmasq.log" &
sleep 2

FLOOD_CODE='
import os, threading
from macabre.attacks.dhcp_offer_flooding import OfferFloodConfig, run_offer_flooding
stop = threading.Event()
threading.Timer(float(os.environ["ATTACK_SECONDS"]), stop.set).start()
stats = run_offer_flooding(
    OfferFloodConfig(iface="h-att", network="10.99.0.128/25", offers_per_discover=10),
    stop,
    lambda _: None,
)
print(f"Flood: answered {stats.discovers} DISCOVERs with {stats.offers} offers")
'

# A client that sends DISCOVERs and records every offer with its transaction ID.
CLIENT_CODE='
import os, random, time
from scapy.all import AsyncSniffer, sendp, BOOTP, DHCP
from macabre.attacks.dhcp_starvation import build_discover

MAC = os.environ["CLIENT_MAC"]
ROUNDS = int(os.environ["ROUNDS"])
rng = random.Random()
seen = []

def on_packet(pkt):
    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP) and pkt[BOOTP].op == 2:
        seen.append(pkt)

def options(pkt):
    return {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}

sniffer = AsyncSniffer(iface="h-cli", store=False, prn=on_packet)
sniffer.start()
time.sleep(0.5)
totals = {"offers": 0, "flood_offers": 0, "first_flood": 0}
for n in range(1, ROUNDS + 1):
    xid = rng.getrandbits(32)
    seen.clear()
    sendp(build_discover(MAC, xid), iface="h-cli", verbose=False)
    time.sleep(1.5)
    offers = [p for p in seen if p[BOOTP].xid == xid]
    flood = [p for p in offers if options(p).get("server_id", "").startswith("10.99.0.") and int(options(p)["server_id"].split(".")[-1]) >= 128]
    totals["offers"] += len(offers)
    totals["flood_offers"] += len(flood)
    if not offers:
        print(f"round {n}: no offers")
        continue
    first = offers[0]
    server = options(first).get("server_id")
    is_flood = server in {p and options(p).get("server_id") for p in flood}
    if is_flood:
        totals["first_flood"] += 1
    origin = "flood" if is_flood else "legitimate"
    print(f"round {n}: {len(offers)} offers ({len(flood)} from the flood); first from {origin} server {server}")
sniffer.stop()
offers_total = totals["offers"]
flood_total = totals["flood_offers"]
first_total = totals["first_flood"]
print(f"Client: {offers_total} offers received in {ROUNDS} rounds, {flood_total} of them from the flood; first offer from the flood in {first_total} of {ROUNDS} rounds")
'

run_client() {
    ip netns exec client env PYTHONPATH="$ROOT/src" CLIENT_MAC="$CLIENT_MAC" ROUNDS="$ROUNDS" "$PY" -c "$CLIENT_CODE"
}

echo "Phase 1: baseline, legitimate server only ($ROUNDS rounds)"
run_client | tee "$WORK/baseline.txt"
echo

echo "Phase 2: flood and legitimate server both running for ${ATTACK_SECONDS}s ($ROUNDS rounds)"
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" "$PY" -c "$FLOOD_CODE" &
FLOOD_PID=$!
sleep 2
run_client | tee "$WORK/race.txt"
wait "$FLOOD_PID"
echo

echo "Phase 3: legitimate server stopped, flood running for ${ATTACK_SECONDS}s ($ROUNDS rounds)"
for pid in $(ip netns pids server 2>/dev/null || true); do
    kill "$pid" 2>/dev/null || true
done
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" "$PY" -c "$FLOOD_CODE" &
FLOOD_PID=$!
sleep 2
run_client | tee "$WORK/alone.txt"
wait "$FLOOD_PID"
echo

BASE_FLOOD="$(grep -c 'from flood' "$WORK/baseline.txt" || true)"
BASE_OFFERS="$(grep -o '^Client: [0-9]*' "$WORK/baseline.txt" | awk '{print $2}')"
RACE_FIRST="$(grep -o 'first offer from the flood in [0-9]*' "$WORK/race.txt" | awk '{print $NF}')"
RACE_DELIVERED="$(grep -o '[0-9]* of them from the flood' "$WORK/race.txt" | awk '{print $1}')"
ALONE_FIRST="$(grep -o 'first offer from the flood in [0-9]*' "$WORK/alone.txt" | awk '{print $NF}')"
ALONE_DELIVERED="$(grep -o '[0-9]* of them from the flood' "$WORK/alone.txt" | awk '{print $1}')"

if (( BASE_FLOOD == 0 )); then
    echo "Baseline: $BASE_OFFERS offers in $ROUNDS rounds, all from the legitimate server. OK"
else
    echo "Baseline: flood offers arrived before the attack. Result unreliable."
fi
echo "Race: the flood delivered $RACE_DELIVERED offers, and the first offer came from the flood in $RACE_FIRST of $ROUNDS rounds."
if (( ALONE_FIRST > 0 )); then
    echo "Alone: the flood delivered $ALONE_DELIVERED offers, and the client's first offer came from an invented server in $ALONE_FIRST of $ROUNDS rounds. Vulnerable."
else
    echo "Alone: the client's first offer never came from the flood. Result unreliable."
fi
echo "Not measured: the client's processing cost for the burst."
