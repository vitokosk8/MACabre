#!/usr/bin/env bash
# Isolated MAC flooding lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   attacker --(veth)-- [switch: Linux bridge br0] --(veth)-- victim
#
#   - attacker: MACabre's MAC flooding attack
#   - switch:   Linux bridge, which learns source MACs and floods unknown
#               unicast frames to every other port, like a learning switch
#   - victim:   a host in promiscuous mode that counts the flooded frames
#               it receives although they are not addressed to it
#
# Nothing here touches the host's real network interfaces.
#
# Limitation: the Linux bridge has no CAM table size limit, so this lab
# measures address learning and unknown-unicast flooding, not CAM overflow
# on a real switch (which depends on the vendor and the port security settings).
#
# Usage:
#   sudo scripts/lab/mac_flooding_lab.sh
#   sudo FRAMES=2000 scripts/lab/mac_flooding_lab.sh
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
SNIFF_SECONDS=20
WORK="$(mktemp -d)"
VICTIM_COUNT="$WORK/victim_count"

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

# attacker <-> switch port sw-a
ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

# victim <-> switch port sw-v
ip link add v-sw type veth peer name sw-v
ip link set v-sw netns victim
ip link set sw-v netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-a sw-v; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec attacker ip link set a-sw up
ip netns exec victim ip link set v-sw up
ip netns exec victim ip link set v-sw promisc on
ip netns exec victim ip addr add 10.98.0.2/24 dev v-sw

learned_addresses() {
    local n
    n=$(ip netns exec switch bridge fdb show br br0 | grep -v permanent | grep -c . || true)
    echo "${n:-0}"
}

# Victim counts flooded frames (EtherType 0x88B5) for a fixed time window.
ip netns exec victim env PYTHONPATH="$ROOT/src" "$PY" -c "
from scapy.all import sniff
count = 0
def cb(pkt):
    global count
    if pkt.type == 0x88B5:
        count += 1
sniff(iface='v-sw', prn=cb, timeout=$SNIFF_SECONDS, store=False)
open('$VICTIM_COUNT', 'w').write(str(count))
" &
sniffer_pid=$!
sleep 2

echo "Sending $FRAMES flood frames from the attacker..."
ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "
import os, threading
from macabre.attacks.mac_flooding import MacFloodingConfig, run_flooding
count = int(os.environ['FRAMES'])
stats = run_flooding(
    MacFloodingConfig(iface='a-sw', count=count, interval=0.0),
    threading.Event(),
    lambda _: None,
)
print(f'Attacker: frames sent {stats.frames}')
"

wait "$sniffer_pid" || true
received=$(cat "$VICTIM_COUNT" 2>/dev/null || echo 0)

echo
echo "Switch and victim results:"
echo "  addresses learned by the switch:          $(learned_addresses)"
echo "  flooded frames received by the victim:    $received of $FRAMES"
echo
echo "Note: this Linux bridge has no CAM size limit, so the table is not"
echo "exhausted here. A real switch with port security would stop learning"
echo "new addresses once its limit is reached."
