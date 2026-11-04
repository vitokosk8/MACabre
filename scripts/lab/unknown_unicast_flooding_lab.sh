#!/usr/bin/env bash
# Isolated unknown unicast flooding lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   victim   --(veth)-- [switch: bridge br0, port p-vic]
#   monitor  --(veth)-- [switch: bridge br0, port p-mon]   (runs MACabre's listener)
#   attacker --(veth)-- [switch: bridge br0, port p-att]   (idle: nothing is sent from it)
#
#   switch:   a Linux bridge. It has never learned UNKNOWN_DST, so frames to it are flooded.
#   victim:   sends unicast frames to UNKNOWN_DST, a host that is not on the bridge.
#   monitor:  MACabre's unknown unicast flooding listener, on p-mon. It counts unicast frames
#             addressed to other hosts.
#
#   Phase 0 (baseline): the listener runs with no traffic. It counts nothing.
#   Phase 1 (flood): the victim sends FRAMES unicast frames to UNKNOWN_DST. The listener should
#                    count them all, even though it is not the destination. The switch should
#                    learn only the victim's MAC, not UNKNOWN_DST.
#
# What this shows: the switch floods unicast frames for an unknown destination to a host on
# another port, and MACabre's listener captures them.
#
# What it does not show: whether a real switch rate-limits or floods these frames, and how
# long its table keeps addresses before they become unknown. Those need a real switch.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/unknown_unicast_flooding_lab.sh
#   sudo FRAMES=20 scripts/lab/unknown_unicast_flooding_lab.sh
#
# Requirements: iproute2 (ip, bridge) and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-10}"
WINDOW=6
VICTIM_MAC="02:00:00:00:00:50"
ATTACKER_MAC="02:00:00:00:00:30"
MONITOR_MAC="02:00:00:00:00:60"
UNKNOWN_DST="02:00:00:00:00:99"
WORK="$(mktemp -d)"
chmod 755 "$WORK"

stop_lab() {
    for ns in victim monitor attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

stop_lab

ip netns add switch
ip netns add victim
ip netns add monitor
ip netns add attacker

for pair in "vic:victim:$VICTIM_MAC" "mon:monitor:$MONITOR_MAC" "att:attacker:$ATTACKER_MAC"; do
    name="$(echo "$pair" | cut -d: -f1)"
    ns="$(echo "$pair" | cut -d: -f2)"
    mac="$(echo "$pair" | cut -d: -f3-)"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns switch
    ip netns exec "$ns" ip link set "h-$name" address "$mac"
    ip netns exec "$ns" ip link set "h-$name" up
    ip netns exec switch ip link set "p-$name" up
done

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for name in vic mon att; do
    ip netns exec switch ip link set "p-$name" master br0
done

# The victim's own MAC is learned from its traffic: one frame to the broadcast address.
HELLO_CODE='
import os
from scapy.all import Ether, Raw, sendp
sendp(Ether(src=os.environ["VICTIM_MAC"], dst="ff:ff:ff:ff:ff:ff", type=0x88B5) / Raw(b"hello"), iface="h-vic", verbose=False)
'

# The victim sends FRAMES unicast frames to UNKNOWN_DST, a host the switch has not learned.
FLOOD_CODE='
import os
from scapy.all import Ether, Raw, sendp
frame = Ether(src=os.environ["VICTIM_MAC"], dst=os.environ["UNKNOWN_DST"], type=0x88B5) / Raw(b"to an unknown host")
for _ in range(int(os.environ["FRAMES"])):
    sendp(frame, iface="h-vic", verbose=False)
'

# MACabre's listener on the monitor port. Prints the flooded frames it counted, then the number of
# distinct destinations.
LISTEN_CODE='
import os, threading
from macabre.attacks.unknown_unicast_flooding import UnknownUnicastConfig, run_unknown_unicast_flooding
stats = run_unknown_unicast_flooding(
    UnknownUnicastConfig(iface="h-mon", duration=float(os.environ["WINDOW"])),
    threading.Event(),
    lambda s: None,
    own_mac=os.environ["MONITOR_MAC"],
)
print(stats.frames, len(stats.destinations))
'

# Number of learned (non-permanent) addresses on a bridge port.
learned_on() {
    ip netns exec switch bridge fdb show br br0 | awk -v p="$1" '$2 == "dev" && $3 == p && !/permanent/' | wc -l
}

# The port a MAC is learned on, or "none".
port_of() {
    ip netns exec switch bridge fdb show br br0 | awk -v m="$1" '$1 == m {print $3; exit}' | grep . || echo none
}

listen() {
    ip netns exec monitor env PYTHONPATH="$ROOT/src" MONITOR_MAC="$MONITOR_MAC" WINDOW="$WINDOW" \
        "$PY" -c "$LISTEN_CODE" 2>/dev/null
}

echo "Phase 0: baseline, the listener runs with no traffic"
BASE="$(listen)"
read -r BASE_FRAMES BASE_DESTS <<< "$BASE"
echo "  unicast frames to other hosts: $BASE_FRAMES"
echo

echo "Phase 1: flood, the victim sends $FRAMES unicast frames to $UNKNOWN_DST, which the switch has not learned"
ip netns exec victim env PYTHONPATH="$ROOT/src" VICTIM_MAC="$VICTIM_MAC" \
    "$PY" -c "$HELLO_CODE" >/dev/null 2>&1
sleep 1
listen > "$WORK/flood.txt" &
LISTEN_PID=$!
sleep 1
ip netns exec victim env PYTHONPATH="$ROOT/src" VICTIM_MAC="$VICTIM_MAC" UNKNOWN_DST="$UNKNOWN_DST" FRAMES="$FRAMES" \
    "$PY" -c "$FLOOD_CODE" >/dev/null 2>&1
wait "$LISTEN_PID"
read -r FLOOD_FRAMES FLOOD_DESTS < "$WORK/flood.txt"
VICTIM_PORT="$(port_of "$VICTIM_MAC")"
UNKNOWN_PORT="$(port_of "$UNKNOWN_DST")"
LEARNED="$(learned_on p-vic)"
echo "  unicast frames to other hosts seen by the listener: $FLOOD_FRAMES of $FRAMES"
echo "  distinct destinations seen: $FLOOD_DESTS"
echo "  switch entry for the victim's MAC: $VICTIM_PORT"
echo "  switch entry for the unknown destination: $UNKNOWN_PORT"
echo "  addresses learned on the victim's port: $LEARNED"
echo

if [[ "$BASE_FRAMES" == "0" && "$FLOOD_FRAMES" == "$FRAMES" && "$FLOOD_DESTS" == "1" \
    && "$VICTIM_PORT" == "p-vic" && "$UNKNOWN_PORT" == "none" ]]; then
    echo "Result: the switch flooded $FLOOD_FRAMES unicast frames for an unknown destination, and the listener on another port captured all of them. The switch did not learn the unknown destination, and the victim's address is the only one learned on the victim's port. Rate limiting and table aging need a real switch."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
