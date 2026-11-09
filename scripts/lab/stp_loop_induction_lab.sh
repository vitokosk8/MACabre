#!/usr/bin/env bash
# Isolated STP loop induction lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   switch:   a Linux bridge (br0) with 802.1D STP on. Ports sw-p1, sw-p2 lead to the attacker,
#             sw-p3 leads to the host.
#   attacker: two interfaces (a1, a2) bridged by MACabre's module (macabre.attacks.stp_loop_induction).
#   host:     injects one broadcast frame after the switch has converged.
#
# Phases:
#   control: the attacker bridge runs STP. It blocks one of its own ports, so the switch sees no loop.
#            Expected: one switch port in blocking, and the RX counters of the switch ports stay low.
#   attack:  the attacker bridge runs no STP and drops STP BPDUs. Both switch ports stay forwarding,
#            and the injected traffic circulates through the loop. Expected: both switch ports
#            forwarding, and the RX counters of the switch ports grow far above the control.
#
# Evidence per phase: the state of sw-p1 and sw-p2, and the RX packet counters of sw-p1 and sw-p2
# over the measurement window. The lab does not use broadcast counts: with IPv6 enabled, the
# loop carries the router solicitations and MLD reports of the namespaces, which is what the
# counters measure. The lab keeps IPv6 enabled for that reason.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/stp_loop_induction_lab.sh
#   sudo WINDOW=30 scripts/lab/stp_loop_induction_lab.sh
#
# Exit 0 when control and attack both show the expected result. Exit 1 when either does not.
# Exit 2 when the setup failed.
#
# Requirements: iproute2 (ip, bridge), and the project virtualenv (.venv) with scapy.
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
STP_CONVERGE_SECONDS="${STP_CONVERGE_SECONDS:-30}"   # forward delay 4 s + max age 6 s + margin
WINDOW="${WINDOW:-20}"                               # seconds over which RX counters are measured
THRESHOLD="${THRESHOLD:-1000}"                       # RX packets over WINDOW that count as a loop
ATTACKER_PID=""

stop_lab() {
    stop_attacker
    for ns in host atk sw; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_attacker() {
    if [[ -n "$ATTACKER_PID" ]] && kill -0 "$ATTACKER_PID" 2>/dev/null; then
        kill -TERM "$ATTACKER_PID" 2>/dev/null || true
        wait "$ATTACKER_PID" 2>/dev/null || true
    fi
    ATTACKER_PID=""
}

rx_packets() {
    ip netns exec sw cat "/sys/class/net/$1/statistics/rx_packets"
}

port_state() {
    ip netns exec sw bridge link show dev "$1" | grep -o 'state [a-z]*' | awk '{print $2}'
}

mk_veth() {
    ip link add "$1" type veth peer name "$2"
    ip link set "$1" netns "$3"
    ip link set "$2" netns "$4"
}

build_topology() {
    for ns in sw atk host; do
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
    done
    mk_veth p1 a1 sw atk
    mk_veth p2 a2 sw atk
    mk_veth p3 h0 sw host
    ip netns exec sw ip link add br0 type bridge stp_state 1 forward_delay 400 hello_time 200 max_age 600
    for p in p1 p2 p3; do
        ip netns exec sw ip link set "$p" master br0
        ip netns exec sw ip link set "$p" up
    done
    ip netns exec sw ip link set br0 up
    ip netns exec host ip link set h0 up
}

run_phase() {
    local phase="$1" attacker_args=()
    echo "=== $phase ==="
    ip netns del sw 2>/dev/null || true
    ip netns del atk 2>/dev/null || true
    ip netns del host 2>/dev/null || true
    build_topology

    if [[ "$phase" == control ]]; then
        attacker_args+=(--run-stp)
    fi
    ip netns exec atk "$PY" -m macabre.attacks.stp_loop_induction a1 a2 "${attacker_args[@]}" \
        > "/tmp/stp_loop_attacker_$phase.log" 2>&1 &
    ATTACKER_PID=$!

    # Wait for the attacker's bridge to exist before the switch starts counting.
    for _ in $(seq 1 20); do
        if ip netns exec atk ip link show br-loop >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
    if ! ip netns exec atk ip link show br-loop >/dev/null 2>&1; then
        echo "The attacker bridge did not appear. See /tmp/stp_loop_attacker_$phase.log" >&2
        return 2
    fi

    echo "waiting ${STP_CONVERGE_SECONDS} s for STP to converge"
    sleep "$STP_CONVERGE_SECONDS"
    echo "switch port states: p1=$(port_state p1) p2=$(port_state p2) p3=$(port_state p3)"

    local rx1_0 rx2_0 rx1_1 rx2_1
    rx1_0=$(rx_packets p1); rx2_0=$(rx_packets p2)
    ip netns exec host "$PY" -c "from scapy.all import Ether, Raw, sendp; sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/Raw(b'MACabre STP loop probe'), iface='h0', verbose=False)"
    sleep "$WINDOW"
    rx1_1=$(rx_packets p1); rx2_1=$(rx_packets p2)

    local delta1=$((rx1_1 - rx1_0)) delta2=$((rx2_1 - rx2_0))
    echo "RX packets over ${WINDOW} s: p1=$delta1 p2=$delta2"

    stop_attacker
    ip netns del sw 2>/dev/null || true
    ip netns del atk 2>/dev/null || true
    ip netns del host 2>/dev/null || true
    printf '%s %s %s\n' "$delta1" "$delta2" "$phase" >> "$RESULTS"
}

RESULTS="$(mktemp)"
trap 'stop_lab; rm -f "$RESULTS"' EXIT

run_phase control
run_phase attack

read -r c1 c2 _ < <(grep ' control$' "$RESULTS")
read -r a1 a2 _ < <(grep ' attack$' "$RESULTS")

echo
echo "control: p1=$c1 p2=$c2 (threshold $THRESHOLD)"
echo "attack:  p1=$a1 p2=$a2 (threshold $THRESHOLD)"

control_ok=0; attack_ok=0
if (( c1 < THRESHOLD && c2 < THRESHOLD )); then control_ok=1; fi
if (( a1 >= THRESHOLD && a2 >= THRESHOLD )); then attack_ok=1; fi

if (( control_ok && attack_ok )); then
    echo "PASS: the control stays quiet and the attack sustains a loop."
    exit 0
fi
echo "FAIL: control_ok=$control_ok attack_ok=$attack_ok"
exit 1
