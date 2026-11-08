#!/usr/bin/env bash
# Isolated proxy ARP lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   attacker --(veth)-- [router: r-left 10.1.0.1/24 | r-right 10.2.0.1/24] --(veth)-- host
#   attacker: 10.1.0.30/24, on the left segment, MACabre's proxy ARP probe.
#   host:     10.2.0.50/24, on the right segment. The attacker should not reach it directly.
#   router:   forwards between the two segments. Its left interface has proxy ARP set or not.
#
#   Phase 0 (baseline): proxy ARP is off on the router's left interface. The probe asks for
#                       10.2.0.50 and gets no answer.
#   Phase 1 (proxy ARP on): the router answers for 10.2.0.50 with its own left MAC.
#
# What this shows: whether proxy ARP on the router's left interface answers for an address on
# the other segment, and which MAC answers. The probe sends requests only.
#
# What it does not show: the router's policy on other interfaces, or other vendors' defaults.
# Those need the target device.
#
# If the kernel does not expose proxy_arp in a new namespace, the lab reports inconclusive
# instead of guessing.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/proxy_arp_abuse_lab.sh
#
# Requirements: iproute2 (ip) and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip sysctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
ATTACKER_IP="10.1.0.30"
ROUTER_LEFT_IP="10.1.0.1"
ROUTER_LEFT_MAC="02:00:00:00:00:01"
ROUTER_RIGHT_IP="10.2.0.1"
HOST_IP="10.2.0.50"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in attacker router host; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

stop_lab

ip netns add attacker
ip netns add router
ip netns add host

# attacker <-> router left
ip link add h-att type veth peer name r-left
ip link set h-att netns attacker
ip link set r-left netns router
ip netns exec attacker ip link set h-att address 02:00:00:00:00:30
ip netns exec attacker ip addr add "$ATTACKER_IP/24" dev h-att
ip netns exec attacker ip link set h-att up
ip netns exec router ip link set r-left address "$ROUTER_LEFT_MAC"
ip netns exec router ip addr add "$ROUTER_LEFT_IP/24" dev r-left
ip netns exec router ip link set r-left up
ip netns exec router ip link set lo up

# router right <-> host
ip link add r-right type veth peer name h-host
ip link set r-right netns router
ip link set h-host netns host
ip netns exec router ip link set r-right address 02:00:00:00:00:02
ip netns exec router ip addr add "$ROUTER_RIGHT_IP/24" dev r-right
ip netns exec router ip link set r-right up
ip netns exec host ip link set h-host address 02:00:00:00:00:50
ip netns exec host ip addr add "$HOST_IP/24" dev h-host
ip netns exec host ip link set h-host up
ip netns exec host ip link set lo up

# Forwarding, so the router routes between the two segments.
ip netns exec router sysctl -q -w net.ipv4.ip_forward=1

if ! ip netns exec router sh -c 'echo 0 > /proc/sys/net/ipv4/conf/r-left/proxy_arp' 2>/dev/null; then
    echo "Result: inconclusive. proxy_arp cannot be set on the router's interface in a new network namespace on this kernel, so the router's answer cannot be controlled here. Test on a real router."
    exit 2
fi

# Asks for HOST_IP from the attacker's segment and prints the MAC that answered, or "none".
PROBE_CODE='
import os, threading
from macabre.attacks.proxy_arp_abuse import ProxyArpProbeConfig, run_proxy_arp_probe
stats = run_proxy_arp_probe(
    ProxyArpProbeConfig(iface="h-att", sender_ip=os.environ["SENDER_IP"], prefix_length=24,
                        targets=(os.environ["TARGET_IP"],), timeout=2.0),
    threading.Event(),
    lambda _s: None,
)
print(stats.answers.get(os.environ["TARGET_IP"], "none"))
'

probe() {
    ip netns exec attacker env PYTHONPATH="$ROOT/src" SENDER_IP="$ATTACKER_IP" TARGET_IP="$HOST_IP" \
        "$PY" -c "$PROBE_CODE" 2>/dev/null | tail -1
}

set_proxy_arp() {
    ip netns exec router sh -c "echo $1 > /proc/sys/net/ipv4/conf/r-left/proxy_arp"
}

echo "Phase 0: baseline, proxy ARP is off on the router's left interface"
set_proxy_arp 0
BASE="$(probe)"
echo "  MAC that answered for $HOST_IP: $BASE"
echo

echo "Phase 1: proxy ARP on, the router's left interface answers for addresses it routes"
set_proxy_arp 1
AFTER="$(probe)"
echo "  MAC that answered for $HOST_IP: $AFTER"
echo

if [[ "$BASE" == "none" && "$AFTER" == "$ROUTER_LEFT_MAC" ]]; then
    echo "Result: with proxy ARP off, nothing answered for $HOST_IP on the other segment. With proxy ARP on, the router answered with its left MAC $ROUTER_LEFT_MAC, so the attacker can send traffic for $HOST_IP to the router. Other vendors' defaults need the target device."
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
