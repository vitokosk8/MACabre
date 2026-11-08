#!/usr/bin/env bash
# Isolated static MAC impersonation lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   victim --(veth)-- [switch: bridge br0, port p-vic, static entry for the victim MAC]
#                     [port p-att] --(veth)-- attacker
#                     [port p-mon] --(veth)-- monitor
#
#   switch:   a bridge with a static FDB entry that binds the victim's MAC to p-vic.
#   attacker: MACabre's static MAC impersonation sender, on p-att.
#   monitor:  counts the frames it receives with each source MAC.
#
#   Phase 0 (baseline): nothing is sent, so the monitor receives nothing.
#   Phase 1 (control): the attacker sends frames with its own MAC. The switch learns that MAC
#            on p-att, and the monitor receives every frame.
#   Phase 2 (impersonation): the attacker sends frames with the victim's registered MAC from
#            p-att. Then the monitor sends unicast frames to the victim's MAC. Checked: whether
#            the static entry moved to p-att, and where that unicast traffic arrives.
#
# What this shows: whether frames that claim a statically registered MAC from another port
# move that binding on this bridge, so traffic for the registered MAC reaches the attacker.
# It does not show what a real switch does: many keep static bindings, and port security may
# drop the frames. Those need a real switch.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/static_mac_impersonation_lab.sh
#   sudo FRAMES=20 scripts/lab/static_mac_impersonation_lab.sh
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
ATTACKER_MAC="02:00:00:00:00:30"
VICTIM_MAC="02:00:00:00:00:50"
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

for pair in "vic:victim:$VICTIM_MAC" "att:attacker:$ATTACKER_MAC" "mon:monitor:02:00:00:00:00:60"; do
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

# The static binding: the victim's MAC is registered on p-vic.
ip netns exec switch bridge fdb add "$VICTIM_MAC" dev p-vic master static

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

# Sends FRAMES frames from the attacker, with the source MAC in SOURCE_MAC.
SEND_CODE='
import os, threading
from macabre.attacks.static_mac_impersonation import StaticMacImpersonationConfig, run_static_mac_impersonation
run_static_mac_impersonation(
    StaticMacImpersonationConfig(iface="h-att", source_mac=os.environ["SOURCE_MAC"],
                                 rate=50, count=int(os.environ["FRAMES"])),
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

# Runs one watcher in namespace $1 on interface $2, writing its count to $3.
# Arguments: namespace, interface, output file, destination filter, source filter.
watch() {
    ip netns exec "$1" env PYTHONPATH="$ROOT/src" WATCH_IFACE="$2" WATCH_DST="${4:-}" WATCH_SRC="${5:-}" \
        WINDOW="$WINDOW" "$PY" -c "$WATCH_CODE" > "$3"
}

binding() {
    ip netns exec switch bridge fdb show br br0 | grep -i "$1" | awk '{print $3}' | head -1
}

reset_binding() {
    ip netns exec switch bridge fdb replace "$VICTIM_MAC" dev p-vic master static
}

echo "Phase 0: baseline, nothing sent"
watch monitor h-mon "$WORK/base.txt" "" "$ATTACKER_MAC" &
sleep 1
wait
BASE="$(cat "$WORK/base.txt")"
echo "  monitor received from the attacker's MAC: $BASE"
echo "  switch entry for the registered MAC: $(binding "$VICTIM_MAC")"
echo

echo "Phase 1: control, the attacker sends $FRAMES frames with its own MAC $ATTACKER_MAC"
watch monitor h-mon "$WORK/control.txt" "" "$ATTACKER_MAC" &
WATCH_PID=$!
sleep 1
ip netns exec attacker env PYTHONPATH="$ROOT/src" SOURCE_MAC="$ATTACKER_MAC" FRAMES="$FRAMES" \
    "$PY" -c "$SEND_CODE" >/dev/null 2>&1
wait "$WATCH_PID"
CONTROL="$(cat "$WORK/control.txt")"
CONTROL_PORT="$(binding "$ATTACKER_MAC")"
echo "  monitor received: $CONTROL of $FRAMES"
echo "  switch entry for the attacker's MAC: ${CONTROL_PORT:-none}"
echo

echo "Phase 2: impersonation, the attacker sends $FRAMES frames with the registered MAC $VICTIM_MAC from p-att"
reset_binding
watch monitor h-mon "$WORK/imp.txt" "" "$VICTIM_MAC" &
WATCH_PID=$!
sleep 1
ip netns exec attacker env PYTHONPATH="$ROOT/src" SOURCE_MAC="$VICTIM_MAC" FRAMES="$FRAMES" \
    "$PY" -c "$SEND_CODE" >/dev/null 2>&1
wait "$WATCH_PID"
IMPERSONATION="$(cat "$WORK/imp.txt")"
MOVED_PORT="$(binding "$VICTIM_MAC")"
echo "  monitor received frames claiming the registered MAC: $IMPERSONATION of $FRAMES"
echo "  switch entry for the registered MAC after the frames: ${MOVED_PORT:-none}"
echo

echo "Phase 3: the monitor sends $FRAMES unicast frames to the registered MAC"
watch attacker h-att "$WORK/to_attacker.txt" "$VICTIM_MAC" "" &
ATT_PID=$!
watch victim h-vic "$WORK/to_victim.txt" "$VICTIM_MAC" "" &
VIC_PID=$!
sleep 1
ip netns exec monitor env PYTHONPATH="$ROOT/src" TARGET_MAC="$VICTIM_MAC" FRAMES="$FRAMES" \
    "$PY" -c "$UNICAST_CODE"
wait "$ATT_PID" "$VIC_PID"
TO_ATTACKER="$(cat "$WORK/to_attacker.txt")"
TO_VICTIM="$(cat "$WORK/to_victim.txt")"
echo "  delivered to the attacker: $TO_ATTACKER of $FRAMES"
echo "  delivered to the victim: $TO_VICTIM of $FRAMES"
echo

if [[ "$BASE" == "0" && "$CONTROL" == "$FRAMES" && "$CONTROL_PORT" == "p-att" \
    && "$IMPERSONATION" == "$FRAMES" && "$MOVED_PORT" == "p-att" \
    && "$TO_ATTACKER" -gt 0 && "$TO_VICTIM" == "0" ]]; then
    echo "Result: frames that claimed the registered MAC from p-att moved its static binding to p-att, and unicast traffic for that MAC then reached the attacker instead of the victim. On this Linux bridge the static flag does not protect the binding. Real switches may keep static bindings or drop the frames; test on a real switch."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
