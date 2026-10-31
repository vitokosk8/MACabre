#!/usr/bin/env bash
# Isolated MAC flapping lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   attacker port A --(veth)-- [switch: Linux bridge br0] --(veth)-- victim
#   attacker port B --(veth)--        |
#                                     +-- (second attacker port, same bridge)
#
#   - attacker: MACabre's MAC flapping attack, one interface per switch port,
#               both sending frames with the same target source MAC
#   - switch:   Linux bridge that learns source MACs; every time the target MAC
#               is seen on a different port, the bridge moves its entry
#   - victim:   a plain host on the third port, only there for realism
#
# The lab counts how many times the switch moved the target MAC between the
# two ports. `bridge monitor fdb` reports every change of the forwarding table.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/mac_flapping_lab.sh
#   sudo FRAMES=2000 scripts/lab/mac_flapping_lab.sh
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
export FRAMES="${FRAMES:-500}"
TARGET_MAC="02:00:00:00:00:10"
WORK="$(mktemp -d)"
FDB_LOG="$WORK/fdb.log"

stop_lab() {
    for ns in victim attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
ip netns add attacker
ip netns add victim

# attacker port A <-> switch port sw-a
ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

# attacker port B <-> switch port sw-b
ip link add b-sw type veth peer name sw-b
ip link set b-sw netns attacker
ip link set sw-b netns switch

# victim <-> switch port sw-v
ip link add v-sw type veth peer name sw-v
ip link set v-sw netns victim
ip link set sw-v netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-a sw-b sw-v; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec attacker ip link set a-sw up
ip netns exec attacker ip link set b-sw up
ip netns exec victim ip link set v-sw up
ip netns exec victim ip addr add 10.97.0.2/24 dev v-sw

# Record every forwarding table change in the background.
ip netns exec switch bridge monitor fdb > "$FDB_LOG" 2>&1 &
monitor_pid=$!
sleep 1

echo "Flapping $TARGET_MAC between two ports with $FRAMES frames..."
ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "
import os, threading
from macabre.attacks.mac_flapping import MacFlappingConfig, run_flapping
count = int(os.environ['FRAMES'])
stats = run_flapping(
    MacFlappingConfig(
        iface_a='a-sw',
        iface_b='b-sw',
        target_mac='$TARGET_MAC',
        count=count,
        interval=0.0,
    ),
    threading.Event(),
    lambda _: None,
)
print(f'Attacker: frames sent {stats.frames}')
"

sleep 1
kill "$monitor_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true

# Each change of the target entry to a new port is one "added" event on sw-a or sw-b.
moves=$(grep -i "$TARGET_MAC" "$FDB_LOG" | grep -c -E 'dev sw-(a|b)' || true)
ports_seen=$(grep -i "$TARGET_MAC" "$FDB_LOG" | grep -o -E 'dev sw-(a|b)' | sort -u | wc -l || true)

echo
echo "Switch results for $TARGET_MAC:"
echo "  entry moves between ports:  ${moves:-0} of $FRAMES frames"
echo "  distinct ports used:        ${ports_seen:-0}"
echo
echo "A moves count close to the frame count means the switch relearned the"
echo "address on every frame. Linux bridge events can merge when frames arrive"
echo "faster than the monitor reads them, so a small gap is expected."
