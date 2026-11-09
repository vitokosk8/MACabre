#!/usr/bin/env bash
# Isolated L2 loop amplification lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   switch:   a Linux bridge (br0). Port sw-p1 and sw-p2 (when there is a loop) lead to the attacker,
#             sw-p3 leads to the sender.
#   attacker: a1 and a2 (a2 only when there is a loop). In the loop phases they are bridged by
#             MACabre's module (macabre.attacks.stp_loop_induction).
#   sender:   injects one broadcast frame with a random source MAC (macabre.attacks.l2_loop_amplification).
#
# Phases:
#   baseline: one link, no loop. The injected frame must not come back to the switch.
#   control:  two links. The switch and the attacker bridge run STP. One port is blocked, so the
#             frame must not multiply.
#   attack:   two links, no STP anywhere. The attacker bridge drops STP BPDUs. The frame multiplies.
#
# Evidence per phase: copies, that is frames with the injected destination that re-enter the
# switch from the attacker side during WINDOW seconds (tcpdump -Q in on sw-p1 and sw-p2), and
# the copies per injected frame. The verdict uses copies per frame.
#
# IPv6 stays enabled: its background control traffic does not match the injected destination,
# so it does not change the count.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/l2_loop_amplification_lab.sh
#   sudo WINDOW=30 THRESHOLD=5000 scripts/lab/l2_loop_amplification_lab.sh
#
# Exit 0 when the baseline and control stay quiet and the attack multiplies the frame.
# Exit 1 when any phase does not match. Exit 2 when the setup failed.
#
# Requirements: iproute2 (ip, bridge), tcpdump, and the project virtualenv (.venv) with scapy.
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge tcpdump; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
DST="${DST:-ff:ff:ff:ff:ff:ff}"
WINDOW="${WINDOW:-20}"                       # seconds over which copies are counted
STP_CONVERGE_SECONDS="${STP_CONVERGE_SECONDS:-30}"
THRESHOLD="${THRESHOLD:-1000}"               # copies per frame that count as amplification
CONTROL_MAX="${CONTROL_MAX:-5}"              # copies per frame that count as quiet
ATTACKER_PID=""
RESULTS="$(mktemp)"

stop_attacker() {
    if [[ -n "$ATTACKER_PID" ]] && kill -0 "$ATTACKER_PID" 2>/dev/null; then
        kill -TERM "$ATTACKER_PID" 2>/dev/null || true
        wait "$ATTACKER_PID" 2>/dev/null || true
    fi
    ATTACKER_PID=""
}

stop_lab() {
    stop_attacker
    for ns in host atk sw; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap 'stop_lab; rm -f "$RESULTS"' EXIT

mk_veth() {
    ip link add "$1" type veth peer name "$2"
    ip link set "$1" netns "$3"
    ip link set "$2" netns "$4"
}

port_state() {
    ip netns exec sw bridge link show dev "$1" 2>/dev/null | grep -o 'state [a-z]*' | awk '{print $2}' || echo "absent"
}

# build_topology TWO_LINKS SW_STP
build_topology() {
    local two="$1" sw_stp="$2" ports="p1 p3"
    stop_lab
    for ns in sw atk host; do
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
    done
    mk_veth p1 a1 sw atk
    mk_veth p3 h0 sw host
    if [[ "$two" == 1 ]]; then
        mk_veth p2 a2 sw atk
        ports="p1 p2 p3"
    fi
    ip netns exec sw ip link add br0 type bridge stp_state "$sw_stp" forward_delay 400 hello_time 200 max_age 600
    for p in $ports; do
        ip netns exec sw ip link set "$p" master br0
        ip netns exec sw ip link set "$p" up
    done
    ip netns exec sw ip link set br0 up
    ip netns exec host ip link set h0 up
    ip netns exec atk ip link set a1 up
    if [[ "$two" == 1 ]]; then
        ip netns exec atk ip link set a2 up
    fi
}

# count_copies TWO_LINKS: copies of frames with the injected destination that re-enter the switch
count_copies() {
    local two="$1" c1 c2=0 n1 n2=0
    ip netns exec sw timeout "$WINDOW" tcpdump -Q in -i p1 -nn -l -e "ether dst $DST" 2>/dev/null | wc -l > /tmp/l2_c1.$$ &
    c1=$!
    if [[ "$two" == 1 ]]; then
        ip netns exec sw timeout "$WINDOW" tcpdump -Q in -i p2 -nn -l -e "ether dst $DST" 2>/dev/null | wc -l > /tmp/l2_c2.$$ &
        c2=$!
    fi
    sleep 1
    ip netns exec host "$PY" -m macabre.attacks.l2_loop_amplification h0 --dst "$DST" --frames 1 >/dev/null
    wait "$c1"
    n1=$(cat /tmp/l2_c1.$$)
    if [[ "$two" == 1 ]]; then
        wait "$c2"
        n2=$(cat /tmp/l2_c2.$$)
    fi
    rm -f /tmp/l2_c1.$$ /tmp/l2_c2.$$
    echo $((n1 + n2))
}

# run_phase NAME TWO_LINKS SW_STP ATTACKER_MODE (none|bridge|run-stp) CONVERGE_SECONDS
run_phase() {
    local name="$1" two="$2" sw_stp="$3" mode="$4" converge="$5" extra=() copies
    echo "=== $name ==="
    build_topology "$two" "$sw_stp"
    if [[ "$mode" != none ]]; then
        [[ "$mode" == run-stp ]] && extra+=(--run-stp)
        ip netns exec atk "$PY" -m macabre.attacks.stp_loop_induction a1 a2 "${extra[@]}" \
            > "/tmp/l2_loop_attacker_$name.log" 2>&1 &
        ATTACKER_PID=$!
        for _ in $(seq 40); do
            ip netns exec atk ip link show br-loop >/dev/null 2>&1 && break
            sleep 0.5
        done
        if ! ip netns exec atk ip link show br-loop >/dev/null 2>&1; then
            echo "The attacker bridge did not appear. See /tmp/l2_loop_attacker_$name.log" >&2
            return 2
        fi
    fi
    echo "waiting ${converge} s for the topology to settle"
    sleep "$converge"
    echo "switch port states: p1=$(port_state p1) p2=$(port_state p2) p3=$(port_state p3)"
    copies=$(count_copies "$two")
    echo "copies re-entering the switch in ${WINDOW} s: $copies (one injected frame)"
    stop_attacker
    printf '%s %s\n' "$copies" "$name" >> "$RESULTS"
}

run_phase baseline 0 0 none 3
run_phase control 1 1 run-stp "$STP_CONVERGE_SECONDS"
run_phase attack 1 0 bridge 3

copies_of() { awk -v n="$1" '$2 == n {print $1}' "$RESULTS"; }
baseline=$(copies_of baseline)
control=$(copies_of control)
attack=$(copies_of attack)

echo
echo "baseline: $baseline copies per frame (quiet if at most $CONTROL_MAX)"
echo "control:  $control copies per frame (quiet if at most $CONTROL_MAX)"
echo "attack:   $attack copies per frame (amplified if at least $THRESHOLD)"

if (( baseline <= CONTROL_MAX && control <= CONTROL_MAX && attack >= THRESHOLD )); then
    echo "PASS: the loop without protection multiplies the frame; the protected and loop-free phases do not."
    exit 0
fi
echo "FAIL: the phases do not match the expected result."
exit 1
