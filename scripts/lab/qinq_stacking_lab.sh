#!/usr/bin/env bash
# Isolated QinQ / VLAN stacking lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   cust --(veth)-- [edge: bridge br0, vlan_protocol 802.1ad] --(veth)-- prov
#   cust: customer port, sends the stacked frame with MACabre's QinQ module.
#   prov: provider-side observer, captures what the edge forwards.
#   edge: stands in for a provider edge that accepts 802.1ad (S-tag) frames on the customer port.
#
#   Phase 0 (baseline): the customer port is a member only of customer VLAN 20. The frame's
#                       outer service VLAN 100 is not allowed on that port, so it is dropped.
#   Phase 1 (service allowed): the customer port is also a member of service VLAN 100. The
#                       edge forwards the frame, and the observer sees outer tag 100 with
#                       inner tag 20 still in place.
#
# What this shows: whether this bridge's VLAN filter, configured as an 802.1ad bridge, lets a
# customer port choose a service VLAN through the outer tag. Only the outermost tag is
# processed by a bridge, so the inner customer tag passes through unchanged.
#
# What it does not show: how a real provider edge stacks, strips or rewrites tags, or any
# vendor default. Those need the target device with the provider configuration in place.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/qinq_stacking_lab.sh
#
# Requirements: iproute2 (ip, bridge) and the project virtualenv (.venv).
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
PROVIDER_VID=100
CUSTOMER_VID=20
CUST_MAC="02:00:00:00:00:30"
WAIT_SECONDS=3
COUNT=3

stop_lab() {
    for ns in cust edge prov; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add cust
ip netns add edge
ip netns add prov

# cust <-> edge
ip link add h-cust type veth peer name p-cust
ip link set h-cust netns cust
ip link set p-cust netns edge
ip netns exec cust ip link set h-cust address "$CUST_MAC"
ip netns exec cust ip link set h-cust up
ip netns exec cust ip link set lo up

# edge <-> prov
ip link add p-prov type veth peer name h-prov
ip link set p-prov netns edge
ip link set h-prov netns prov
ip netns exec prov ip link set h-prov up
ip netns exec prov ip link set lo up

# The edge bridge: VLAN filtering on, outer tag protocol 802.1ad (S-tag).
ip netns exec edge ip link add br0 type bridge
if ! ip netns exec edge ip link set br0 type bridge vlan_filtering 1 2>/dev/null \
    || ! ip netns exec edge ip link set br0 type bridge vlan_protocol 802.1ad 2>/dev/null; then
    echo "Result: inconclusive. VLAN filtering with an 802.1ad outer tag cannot be set on a bridge on this kernel, so the edge cannot be configured in a namespace here. Test on a real provider edge."
    exit 2
fi
ip netns exec edge ip link set br0 up
ip netns exec edge ip link set p-cust master br0
ip netns exec edge ip link set p-prov master br0
ip netns exec edge ip link set p-cust up
ip netns exec edge ip link set p-prov up
ip netns exec edge ip link set lo up

# The provider side carries the service VLAN tagged.
ip netns exec edge bridge vlan add dev p-prov vid "$PROVIDER_VID"

# Send the frame once with MACabre's module. The observer is started first, in the background.
SENDER_CODE='
import os, threading
from macabre.attacks.qinq_stacking_abuse import QinQStackingConfig, run_qinq_stacking
run_qinq_stacking(
    QinQStackingConfig(iface="h-cust", provider_vid=int(os.environ["PROVIDER_VID"]),
                       customer_vid=int(os.environ["CUSTOMER_VID"]), source_mac=os.environ["CUST_MAC"],
                       frames=int(os.environ["COUNT"])),
    threading.Event(),
    lambda _s: None,
)
'

# Prints how many stacked probes arrived on the provider side, then the outer and inner VIDs of the first.
OBSERVE_CODE='
import os
from scapy.all import Dot1Q, Ether, sniff
MARKER = b"MACabre QinQ stacking probe"
def keep(p):
    return p.haslayer(Ether) and p[Ether].type == 0x88A8 and MARKER in bytes(p)
pkts = sniff(iface="h-prov", timeout=float(os.environ["WAIT_SECONDS"]), lfilter=keep)
print(len(pkts))
if pkts:
    outer = pkts[0][Dot1Q]
    print(f"{outer.vlan} {outer.payload.vlan}")
'

run_phase() {
    local out="$WORK_DIR/observed.txt"
    ip netns exec prov env PYTHONPATH="$ROOT/src" WAIT_SECONDS="$WAIT_SECONDS" \
        "$PY" -c "$OBSERVE_CODE" > "$out" 2>/dev/null &
    local obs_pid=$!
    sleep 1
    ip netns exec cust env PYTHONPATH="$ROOT/src" PROVIDER_VID="$PROVIDER_VID" \
        CUSTOMER_VID="$CUSTOMER_VID" CUST_MAC="$CUST_MAC" COUNT="$COUNT" \
        "$PY" -c "$SENDER_CODE" >/dev/null 2>&1
    wait "$obs_pid" || true
    cat "$out"
}

WORK_DIR="$(mktemp -d)"
trap 'stop_lab; rm -rf "$WORK_DIR"' EXIT

echo "Phase 0: baseline, the customer port is a member only of customer VLAN $CUSTOMER_VID"
ip netns exec edge bridge vlan add dev p-cust vid "$CUSTOMER_VID"
BASE_OUT="$(run_phase)"
BASE_COUNT="$(echo "$BASE_OUT" | sed -n 1p)"
echo "  stacked probes that reached the provider side: ${BASE_COUNT:-0}"
echo

echo "Phase 1: the customer port is also a member of service VLAN $PROVIDER_VID"
ip netns exec edge bridge vlan add dev p-cust vid "$PROVIDER_VID"
SERVICE_OUT="$(run_phase)"
SERVICE_COUNT="$(echo "$SERVICE_OUT" | sed -n 1p)"
SERVICE_TAGS="$(echo "$SERVICE_OUT" | sed -n 2p)"
echo "  stacked probes that reached the provider side: ${SERVICE_COUNT:-0}"
echo "  outer VLAN and inner VLAN of the first one: ${SERVICE_TAGS:-none}"
echo

if [[ "${BASE_COUNT:-0}" == "0" && "${SERVICE_COUNT:-0}" -ge 1 && "$SERVICE_TAGS" == "$PROVIDER_VID $CUSTOMER_VID" ]]; then
    echo "Result: without service VLAN $PROVIDER_VID on the customer port the edge dropped the stacked frame. With it, the edge forwarded it with outer VLAN $PROVIDER_VID and inner VLAN $CUSTOMER_VID intact, so the customer port chose the service. Provider edges that set the outer tag themselves need the target device."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
