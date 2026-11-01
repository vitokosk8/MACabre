#!/usr/bin/env bash
# Isolated MNDP flooding lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with two hosts attached:
#
#   receiver: a host that listens on UDP port 5678 and decodes every MNDP announcement.
#             It stands in for a RouterOS neighbor list, which is not available on Linux.
#   attacker: MACabre's MNDP flooder. It sends FLOOD_RATE announcements per second for
#             FLOOD_SECONDS seconds, each for a random router, identity and address.
#
# What this lab shows: how many announcements reach the receiver and decode, and how many
# distinct routers they name. It does not show a RouterOS neighbor list filling, and it does
# not measure CPU use. The MNDP field layout is from a third-party description and must be
# checked against a RouterOS capture before this attack is marked as tested.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/mndp_flooding_lab.sh
#   sudo FLOOD_RATE=500 FLOOD_SECONDS=10 scripts/lab/mndp_flooding_lab.sh
#
# Requirements: iproute2 and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
    echo "Missing required tool: ip" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FLOOD_RATE="${FLOOD_RATE:-200}"
FLOOD_SECONDS="${FLOOD_SECONDS:-10}"
WORK="$(mktemp -d)"
chmod 755 "$WORK"

stop_lab() {
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

LISTEN_SECONDS=$(( FLOOD_SECONDS + 4 ))

LISTEN_CODE='
import os, threading
from scapy.all import AsyncSniffer, UDP
from macabre.attacks.mndp_spoofing import parse_mndp, TLV_IDENTITY
frames = []
identities = set()
def on_packet(pkt):
    if pkt.haslayer(UDP) and pkt[UDP].dport == 5678:
        try:
            fields = parse_mndp(bytes(pkt[UDP].payload))
        except ValueError:
            return
        frames.append(1)
        identities.add(fields[TLV_IDENTITY])
sniffer = AsyncSniffer(iface="h-rcv", store=False, prn=on_packet)
sniffer.start()
threading.Event().wait(float(os.environ["LISTEN_SECONDS"]))
sniffer.stop()
print(f"Receiver: decoded {len(frames)} MNDP announcements naming {len(identities)} distinct routers")
'

FLOOD_CODE='
import os, threading
from macabre.attacks.mndp_flooding import MndpFloodingConfig, run_mndp_flooding
rate = float(os.environ["FLOOD_RATE"])
seconds = int(os.environ["FLOOD_SECONDS"])
stats = run_mndp_flooding(
    MndpFloodingConfig(iface="h-att", rate=rate, count=int(rate * seconds)),
    threading.Event(),
    lambda _: None,
)
print(f"Flooder: sent {stats.frames} announcements for random routers over about {seconds} s")
'

echo "Receiver listening for ${LISTEN_SECONDS}s, attacker floods at $FLOOD_RATE per second for $FLOOD_SECONDS s"
ip netns exec receiver env PYTHONPATH="$ROOT/src" LISTEN_SECONDS="$LISTEN_SECONDS" "$PY" -c "$LISTEN_CODE" > "$WORK/receiver.txt" 2>/dev/null &
RECV_PID=$!
sleep 3
ip netns exec attacker env PYTHONPATH="$ROOT/src" FLOOD_RATE="$FLOOD_RATE" FLOOD_SECONDS="$FLOOD_SECONDS" "$PY" -c "$FLOOD_CODE"
wait "$RECV_PID"
cat "$WORK/receiver.txt"
echo

SENT=$(( FLOOD_RATE * FLOOD_SECONDS ))
RECEIVED="$(sed -n 's/^Receiver: decoded \([0-9]*\) .*/\1/p' "$WORK/receiver.txt")"
RECEIVED="${RECEIVED:-0}"
if (( RECEIVED > 0 )); then
    echo "Result: the receiver decoded $RECEIVED of about $SENT announcements sent, each naming a different router. Not yet tested against a RouterOS neighbor list."
else
    echo "Result: the receiver decoded no announcements. Result unreliable."
fi
