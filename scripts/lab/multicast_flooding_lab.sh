#!/usr/bin/env bash
# Isolated multicast flooding lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with two hosts attached:
#
#   sender:   MACabre's multicast flooder. It sends FLOOD_RATE frames per second for
#             FLOOD_SECONDS seconds, each to a random IPv4 multicast group.
#   receiver: a host that has joined no multicast group. It counts the frames it receives.
#
# The bridge has multicast snooping on (the Linux default), and no receiver has joined a
# group, so the bridge does not know which port wants any group. Unknown multicast is
# flooded to every port, and the receiver gets the stream.
#
# Phases:
#   Phase 1 (flood): flooding on. The receiver should get most of the frames.
#   Phase 2 (control): flooding of unknown multicast turned off on the receiver's port.
#            The receiver should get none of them.
#
# The lab measures delivery to a port that never joined a group. It does not measure the
# CPU or link load on a real switch. Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/multicast_flooding_lab.sh
#   sudo FLOOD_RATE=500 FLOOD_SECONDS=10 scripts/lab/multicast_flooding_lab.sh
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
    for ns in sender receiver lan; do
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
ip netns add sender

for pair in "rcv:receiver" "snd:sender"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in rcv snd; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec receiver ip link set h-rcv up
ip netns exec sender ip link set h-snd up

LISTEN_SECONDS=$(( FLOOD_SECONDS + 4 ))

RECEIVE_CODE='
import os, threading
from scapy.all import AsyncSniffer, Ether
count = [0]
def on_packet(pkt):
    if pkt.haslayer(Ether) and pkt[Ether].type == 0x88B5:
        count[0] += 1
sniffer = AsyncSniffer(iface="h-rcv", store=False, prn=on_packet)
sniffer.start()
threading.Event().wait(float(os.environ["SECONDS_TO_LISTEN"]))
try:
    sniffer.stop()
except Exception:
    pass
print(count[0])
'

FLOOD_CODE='
import os, threading
from macabre.attacks.multicast_flooding import MulticastFloodingConfig, run_multicast_flooding
rate = float(os.environ["FLOOD_RATE"])
seconds = int(os.environ["FLOOD_SECONDS"])
stats = run_multicast_flooding(
    MulticastFloodingConfig(iface="h-snd", rate=rate, count=int(rate * seconds)),
    threading.Event(),
    lambda _: None,
)
print(stats.frames)
'

echo "Phase 1: flooding on. $FLOOD_RATE frames per second for $FLOOD_SECONDS s to random groups"
ip netns exec receiver env SECONDS_TO_LISTEN="$LISTEN_SECONDS" "$PY" -c "$RECEIVE_CODE" > "$WORK/flood.txt" 2>/dev/null &
RX=$!
sleep 3
SENT="$(ip netns exec sender env PYTHONPATH="$ROOT/src" FLOOD_RATE="$FLOOD_RATE" FLOOD_SECONDS="$FLOOD_SECONDS" "$PY" -c "$FLOOD_CODE" 2>/dev/null)"
wait "$RX"
GOT_ON="$(cat "$WORK/flood.txt")"
echo "Sender: $SENT frames sent. Receiver, which joined no group: $GOT_ON frames received."
echo

echo "Phase 2: control, flooding of unknown multicast turned off on the receiver's port"
ip netns exec lan ip link set "p-rcv" type bridge_slave mcast_flood off
ip netns exec receiver env SECONDS_TO_LISTEN="$LISTEN_SECONDS" "$PY" -c "$RECEIVE_CODE" > "$WORK/control.txt" 2>/dev/null &
RX=$!
sleep 3
SENT="$(ip netns exec sender env PYTHONPATH="$ROOT/src" FLOOD_RATE="$FLOOD_RATE" FLOOD_SECONDS="$FLOOD_SECONDS" "$PY" -c "$FLOOD_CODE" 2>/dev/null)"
wait "$RX"
GOT_OFF="$(cat "$WORK/control.txt")"
echo "Sender: $SENT frames sent. Receiver: $GOT_OFF frames received."
echo

if (( GOT_ON > 0 )); then
    echo "Flood: the receiver, which joined no group, got $GOT_ON of about $(( FLOOD_RATE * FLOOD_SECONDS )) frames. The bridge flooded unknown multicast to every port. Vulnerable without snooping that learns the group."
else
    echo "Flood: the receiver got no frames. Result unreliable."
fi
if (( GOT_OFF == 0 )); then
    echo "Control: with flooding of unknown multicast off on the receiver's port, it got none."
else
    echo "Control: the receiver still got $GOT_OFF frames with flooding off. Result unreliable."
fi
