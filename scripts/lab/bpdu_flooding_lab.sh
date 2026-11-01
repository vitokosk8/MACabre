#!/usr/bin/env bash
# Isolated BPDU flooding lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   root --(veth)-- [switch: br0 with STP, port sw-r]
#                   [switch port sw-a] --(veth)-- attacker
#                   [switch port sw-m] --(veth)-- monitor
#
#   root:     the real root bridge (priority 8192).
#   switch:   a bridge running 802.1D Spanning Tree (kernel STP).
#   attacker: floods configuration BPDUs from random bridge IDs at the worst priority,
#             so none of them can win the election.
#   monitor:  a host whose MAC the switch learns on sw-m.
#
#   Phase 1 (baseline): the root port is sw-r and the monitor's MAC is learned.
#   Phase 2 (control): ten seconds with no flood, to measure the idle receive rate of sw-a.
#   Phase 3: the attacker floods for FLOOD_SECONDS at FLOOD_RATE frames per second.
#            The lab counts the frames the switch receives on sw-a, and checks that the
#            topology does not change.
#
# This lab shows the flood is delivered at the requested rate, and that the topology
# holds. It does not measure the switch's control-plane load or the delay it adds to
# real spanning-tree updates, so the attack is not marked tested.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/bpdu_flooding_lab.sh
#   sudo FLOOD_RATE=1000 FLOOD_SECONDS=20 scripts/lab/bpdu_flooding_lab.sh
#
# Requirements: iproute2 (ip, bridge), and the project virtualenv (.venv).
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
FLOOD_RATE="${FLOOD_RATE:-500}"
FLOOD_SECONDS="${FLOOD_SECONDS:-10}"
SETTLE_SECONDS=12
ATTACKER_MAC="02:00:00:00:00:30"
MONITOR_MAC="02:00:00:00:00:40"

stop_lab() {
    for ns in monitor attacker root switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add switch
ip netns add root
ip netns add attacker
ip netns add monitor

ip link add r-sw type veth peer name sw-r
ip link set r-sw netns root
ip link set sw-r netns switch

ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

ip link add m-sw type veth peer name sw-m
ip link set m-sw netns monitor
ip link set sw-m netns switch

ip netns exec switch ip link add br0 type bridge stp_state 1 \
    forward_delay 200 hello_time 200 max_age 600
ip netns exec switch ip link set br0 up
for port in sw-a sw-r sw-m; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec root ip link add rb0 type bridge stp_state 1 priority 8192 \
    forward_delay 200 hello_time 200 max_age 600
ip netns exec root ip link set rb0 up
ip netns exec root ip link set r-sw master rb0
ip netns exec root ip link set r-sw up

ip netns exec attacker ip link set a-sw address "$ATTACKER_MAC"
ip netns exec attacker ip link set a-sw up
ip netns exec monitor ip link set m-sw address "$MONITOR_MAC"
ip netns exec monitor ip link set m-sw up

root_port_name() {
    local number port port_no
    number="$(ip netns exec switch ip -d link show br0 | grep -o 'root_port [0-9]*' | awk '{print $2}')"
    if [[ "$number" == "0" || -z "$number" ]]; then
        echo "none"
        return
    fi
    for port in sw-a sw-r sw-m; do
        port_no="$(ip netns exec switch ip -d link show "$port" | grep -o 'port_no 0x[0-9a-f]*' | awk '{print $2}')"
        if (( port_no == number )); then
            echo "$port"
            return
        fi
    done
    echo "port $number"
}

monitor_entry() {
    if ip netns exec switch bridge fdb show br br0 | grep -qi "$MONITOR_MAC"; then
        echo "learned"
    else
        echo "flushed"
    fi
}

# Frames received on sw-a so far (RX packets).
rx_packets() {
    ip netns exec switch ip -s link show sw-a | awk '/RX:/{getline; print $2; exit}'
}

LEARN_CODE='
from scapy.all import Ether, Raw, sendp
sendp(Ether(src="'"$MONITOR_MAC"'", dst="ff:ff:ff:ff:ff:ff", type=0x88B5) / Raw(b"\x00" * 46), iface="m-sw", verbose=False)
'

FLOOD_CODE='
import os
from macabre.attacks.bpdu_flooding import BpduFloodingConfig, run_bpdu_flooding
import threading
rate = float(os.environ["FLOOD_RATE"])
seconds = float(os.environ["FLOOD_SECONDS"])
stats = run_bpdu_flooding(
    BpduFloodingConfig(iface="a-sw", rate=rate, count=int(rate * seconds)),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} BPDUs at {rate:g} per second")
'

echo "Waiting ${SETTLE_SECONDS}s for the real root to be elected"
sleep "$SETTLE_SECONDS"
ip netns exec monitor env PYTHONPATH="$ROOT/src" "$PY" -c "$LEARN_CODE"
sleep 1

echo "Phase 1: baseline"
BASE_PORT="$(root_port_name)"
BASE_MAC="$(monitor_entry)"
echo "  root port: $BASE_PORT   monitor MAC: $BASE_MAC"
echo

echo "Phase 2: control, 10 s with no flood"
C0="$(rx_packets)"
sleep 10
C1="$(rx_packets)"
CONTROL_RX=$(( C1 - C0 ))
echo "  frames received on sw-a: $CONTROL_RX"
echo

echo "Phase 3: attacker floods $FLOOD_RATE BPDUs per second for ${FLOOD_SECONDS}s"
F0="$(rx_packets)"
ip netns exec attacker env PYTHONPATH="$ROOT/src" FLOOD_RATE="$FLOOD_RATE" FLOOD_SECONDS="$FLOOD_SECONDS" \
    "$PY" -c "$FLOOD_CODE" &
FLOOD_PID=$!
sleep $(( ${FLOOD_SECONDS%.*} / 2 ))
MID_PORT="$(root_port_name)"
echo "  mid-flood root port: $MID_PORT"
wait "$FLOOD_PID"
F1="$(rx_packets)"
END_PORT="$(root_port_name)"
END_MAC="$(monitor_entry)"
FLOOD_RX=$(( F1 - F0 ))
EXPECTED=$(( FLOOD_RATE * ${FLOOD_SECONDS%.*} ))
echo "  frames received on sw-a during the flood: $FLOOD_RX (expected about $EXPECTED)"
echo "  end: root port $END_PORT   monitor MAC $END_MAC"
echo

if [[ "$BASE_PORT" == "sw-r" && "$BASE_MAC" == "learned" ]]; then
    echo "Baseline: root port on the real root (sw-r) and the monitor's MAC learned. OK"
else
    echo "Baseline: root port $BASE_PORT, monitor MAC $BASE_MAC. Result unreliable."
fi
if (( CONTROL_RX < 50 )); then
    echo "Control: about $CONTROL_RX frames arrived on sw-a with no flood."
else
    echo "Control: $CONTROL_RX frames arrived with no flood. Result unreliable."
fi
if (( FLOOD_RX * 100 >= EXPECTED * 90 )); then
    echo "Delivery: the switch received $FLOOD_RX of about $EXPECTED flooded BPDUs (at least 90%)."
else
    echo "Delivery: the switch received only $FLOOD_RX of about $EXPECTED flooded BPDUs."
fi
if [[ "$MID_PORT" == "sw-r" && "$END_PORT" == "sw-r" && "$END_MAC" == "learned" ]]; then
    echo "Topology: the root port stayed on the real root and the monitor's MAC stayed learned. The flood did not change the topology."
else
    echo "Topology: the flood changed the topology (mid $MID_PORT, end $END_PORT, monitor MAC $END_MAC)."
fi
echo "Not measured: the switch's control-plane load and the delay it adds to real spanning-tree updates."
