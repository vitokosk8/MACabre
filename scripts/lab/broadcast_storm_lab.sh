#!/usr/bin/env bash
# Isolated broadcast storm lab (Linux only, needs root).
#
# Topology: two Linux bridges (sw1, sw2), each with an attached host. The attacker sits on
# sw1, the receiver on sw2.
#
#   Phase 1 (baseline): one link between the bridges. No loop. The receiver should get
#            every broadcast the attacker sends.
#   Phase 2 (loop, STP on): two links between the bridges, so there is a loop, and STP is
#            enabled on both bridges. STP blocks one link, so each broadcast should reach
#            the receiver once. This is the defense.
#   Phase 3 (loop, STP off): the same two links with STP off. A broadcast circulates the
#            loop and copies itself at each bridge. This phase is opt-in with LOOP_TEST=1,
#            because on this kernel it saturates the lab host within one frame.
#
# The attacker sends FRAMES broadcasts at RATE per second in phase 1 and 2. In phase 3 it
# sends one frame, and the loop is cut after 4 s.
#
# This lab measures copies at the receiver. It does not measure the CPU or link load of a
# real switch. Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/broadcast_storm_lab.sh
#   sudo LOOP_TEST=1 scripts/lab/broadcast_storm_lab.sh
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
FRAMES="${FRAMES:-20}"
RATE="${RATE:-20}"
LOOP_TEST="${LOOP_TEST:-0}"
WORK="$(mktemp -d)"
chmod 755 "$WORK"

stop_lab() {
    for ns in att rcv sw1 sw2; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

# build LOOPS STP : LOOPS is 1 (one link) or 2 (two links); STP is 0 or 1.
build() {
    local loops="$1" stp="$2"
    stop_lab
    for ns in att rcv sw1 sw2; do ip netns add "$ns"; done

    ip link add a-att type veth peer name h-att
    ip link add a-rcv type veth peer name h-rcv
    ip link add l1a type veth peer name l1b
    ip link set h-att netns att; ip link set a-att netns sw1
    ip link set h-rcv netns rcv; ip link set a-rcv netns sw2
    ip link set l1a netns sw1; ip link set l1b netns sw2

    local br_opts=""
    if [[ "$stp" == "1" ]]; then
        br_opts="stp_state 1 forward_delay 200 hello_time 200 max_age 600"
    else
        br_opts="stp_state 0"
    fi
    for ns in sw1 sw2; do
        ip netns exec "$ns" ip link add br0 type bridge $br_opts
        ip netns exec "$ns" ip link set br0 up
    done
    ip netns exec sw1 ip link set a-att master br0
    ip netns exec sw2 ip link set a-rcv master br0
    ip netns exec sw1 ip link set l1a master br0
    ip netns exec sw2 ip link set l1b master br0
    if [[ "$loops" == "2" ]]; then
        ip link add l2a type veth peer name l2b
        ip link set l2a netns sw1; ip link set l2b netns sw2
        ip netns exec sw1 ip link set l2a master br0
        ip netns exec sw2 ip link set l2b master br0
        ip netns exec sw1 ip link set l2a up
        ip netns exec sw2 ip link set l2b up
    fi
    for x in a-att l1a; do ip netns exec sw1 ip link set "$x" up; done
    for x in a-rcv l1b; do ip netns exec sw2 ip link set "$x" up; done
    ip netns exec att ip link set h-att up
    ip netns exec rcv ip link set h-rcv up
}

# Count the broadcast frames (EtherType 0x88B5) the receiver gets during SECONDS.
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

ATTACK_CODE='
import os, threading
from macabre.attacks.broadcast_storm import BroadcastStormConfig, run_broadcast_storm
stats = run_broadcast_storm(
    BroadcastStormConfig(
        iface="h-att",
        rate=float(os.environ["RATE"]),
        payload_size=64,
        count=int(os.environ["COUNT"]),
    ),
    threading.Event(),
    lambda _: None,
)
print(stats.frames)
'

run_receiver() {
    ip netns exec rcv env SECONDS_TO_LISTEN="$1" "$PY" -c "$RECEIVE_CODE" 2>/dev/null
}

run_attacker() {
    ip netns exec att env PYTHONPATH="$ROOT/src" RATE="$1" COUNT="$2" "$PY" -c "$ATTACK_CODE" 2>/dev/null
}

echo "Phase 1: baseline, one link, no loop. $FRAMES broadcasts at $RATE per second"
build 1 0
sleep 1
LISTEN=$(( FRAMES / RATE + 3 ))
run_receiver "$LISTEN" > "$WORK/baseline.txt" &
RX=$!
sleep 0.5
SENT="$(run_attacker "$RATE" "$FRAMES")"
wait "$RX"
GOT="$(cat "$WORK/baseline.txt")"
echo "Sender: $SENT frames sent. Receiver: $GOT broadcasts received."
echo

echo "Phase 2: loop with STP on. One broadcast, STP has converged"
build 2 1
sleep 8
run_receiver 3 > "$WORK/stp.txt" &
RX=$!
sleep 0.5
SENT="$(run_attacker 1 1)"
wait "$RX"
GOT_STP="$(cat "$WORK/stp.txt")"
echo "Sender: $SENT frame sent. Receiver: $GOT_STP broadcast copies received."
echo

if [[ "$LOOP_TEST" == "1" ]]; then
    echo "Phase 3: loop with STP off. One broadcast; the loop is cut after 4 s"
    build 2 0
    sleep 1
    # The receiver listens for 6 s. The attacker needs a second or two to start, so the
    # loop is cut 4 s after the receiver starts, whether or not the frame has been sent.
    run_receiver 6 > "$WORK/storm.txt" &
    RX=$!
    (
        sleep 4
        ip netns exec sw1 ip link set l1a down 2>/dev/null || true
        ip netns exec sw1 ip link set l2a down 2>/dev/null || true
    ) &
    CUT=$!
    sleep 0.5
    set +e
    ip netns exec att env PYTHONPATH="$ROOT/src" RATE=1 COUNT=1 "$PY" -c "$ATTACK_CODE" > "$WORK/sender.txt" 2> "$WORK/sender.err"
    SENDER_STATUS=$?
    set -e
    wait "$CUT" 2>/dev/null || true
    wait "$RX" 2>/dev/null || true
    STORM="$(cat "$WORK/storm.txt" 2>/dev/null || echo 0)"
    echo "Sender: exit $SENDER_STATUS, $(grep -c 'No buffer' "$WORK/sender.err" || true) buffer errors. Receiver: $STORM broadcast copies in 6 s."
    echo
else
    echo "Phase 3: skipped. Set LOOP_TEST=1 to run the loop without STP. It saturates the lab host within one frame."
    echo
fi

if (( GOT == FRAMES )); then
    echo "Baseline: every broadcast reached the receiver. OK"
else
    echo "Baseline: the receiver got $GOT of $FRAMES broadcasts. Result unreliable."
fi
if (( GOT_STP == 1 )); then
    echo "Loop with STP: one broadcast, one copy at the receiver. STP blocked the loop."
else
    echo "Loop with STP: $GOT_STP copies at the receiver for one broadcast. Result unreliable."
fi
if [[ "$LOOP_TEST" == "1" ]]; then
    if (( ${STORM:-0} > 1 )); then
        echo "Loop without STP: one broadcast became ${STORM} copies at the receiver before the loop was cut. Vulnerable with no loop protection."
    else
        echo "Loop without STP: one broadcast did not multiply. Result unreliable."
    fi
fi
