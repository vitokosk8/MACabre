#!/usr/bin/env bash
# Isolated private VLAN isolation bypass lab (Linux only, needs root).
#
# Topology, all inside network namespaces: one bridge (the LAN) with three ports:
#
#   attacker: an isolated port. Its IP is 10.77.0.20. MACabre's module sends the probes.
#   victim:   an isolated port. Its IP is 10.77.0.30. It counts the probes it receives.
#   relay:    a promiscuous port (not isolated), a router at 10.77.0.1 with forwarding on.
#
# Isolation is set on the attacker's and the victim's ports, so the bridge drops frames
# between them. The relay's port is not isolated, so frames may pass between it and either
# isolated port.
#
# Phases:
#   Phase 1 (control): the probes go straight to the victim's MAC. The victim should receive
#            none: the bridge blocks isolated-to-isolated traffic.
#   Phase 2 (bypass): the probes go to the relay's MAC with the victim's IP. The relay forwards
#            them to the victim. The victim should receive them.
#
# What the lab shows: whether the Linux bridge's isolated ports are blocked from each other
# directly, and reached through a promiscuous relay. It does not show a real provider's
# private VLAN configuration, the proxy ARP and VLAN-tag variants, or the relay's own
# filters. Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/private_vlan_bypass_lab.sh
#
# Requirements: iproute2 (ip, bridge), sysctl, and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge sysctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
ATTACKER_MAC="02:00:00:00:00:20"
ATTACKER_IP="10.77.0.20"
VICTIM_MAC="02:00:00:00:00:30"
VICTIM_IP="10.77.0.30"
RELAY_MAC="02:00:00:00:00:01"
RELAY_IP="10.77.0.1"
PROBES=5

stop_lab() {
    for ns in lan attacker victim relay; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add lan
ip netns add attacker
ip netns add victim
ip netns add relay

for pair in "atk:attacker" "vic:victim" "rel:relay"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "p-$name" netns lan
    ip link set "h-$name" netns "$ns"
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in atk vic rel; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
# Attacker and victim are isolated from each other; the relay's port is promiscuous.
ip netns exec lan bridge link set dev p-atk isolated on
ip netns exec lan bridge link set dev p-vic isolated on

ip netns exec attacker ip link set h-atk address "$ATTACKER_MAC"
ip netns exec attacker ip addr add "$ATTACKER_IP/24" dev h-atk
ip netns exec attacker ip link set h-atk up
ip netns exec attacker ip link set lo up

ip netns exec victim ip link set h-vic address "$VICTIM_MAC"
ip netns exec victim ip addr add "$VICTIM_IP/24" dev h-vic
ip netns exec victim ip link set h-vic up
ip netns exec victim ip link set lo up

ip netns exec relay ip link set h-rel address "$RELAY_MAC"
ip netns exec relay ip addr add "$RELAY_IP/24" dev h-rel
ip netns exec relay ip link set h-rel up
ip netns exec relay ip link set lo up
ip netns exec relay sysctl -qw net.ipv4.ip_forward=1

COUNT_CODE='
import os, threading, time
from scapy.all import AsyncSniffer, UDP
count = [0]
def on_packet(pkt):
    if pkt.haslayer(UDP) and bytes(pkt[UDP].payload).startswith(b"MACabre PVLAN probe"):
        count[0] += 1
sniffer = AsyncSniffer(iface="h-vic", store=False, prn=on_packet)
sniffer.start()
time.sleep(float(os.environ["LISTEN_SECONDS"]))
try:
    sniffer.stop()
except Exception:
    pass
print(count[0])
'

SEND_CODE='
import os, threading
from macabre.attacks.private_vlan_bypass import PrivateVlanBypassConfig, run_private_vlan_bypass
relay = os.environ.get("RELAY_MAC", "")
stats = run_private_vlan_bypass(
    PrivateVlanBypassConfig(
        iface="h-atk",
        source_mac=os.environ["ATTACKER_MAC"],
        source_ip=os.environ["ATTACKER_IP"],
        target_mac=os.environ["VICTIM_MAC"],
        target_ip=os.environ["VICTIM_IP"],
        relay_mac=relay,
        probes=int(os.environ["PROBES"]),
    ),
    threading.Event(),
    lambda _s: None,
)
print(stats.probes)
'

run_phase() {
    local relay="$1"
    local rx_out
    rx_out="$(mktemp)"
    ip netns exec victim env LISTEN_SECONDS=6 "$PY" -c "$COUNT_CODE" > "$rx_out" 2>/dev/null &
    local rx=$!
    sleep 2
    local sent
    sent="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
        ATTACKER_IP="$ATTACKER_IP" VICTIM_MAC="$VICTIM_MAC" VICTIM_IP="$VICTIM_IP" RELAY_MAC="$relay" \
        PROBES="$PROBES" "$PY" -c "$SEND_CODE" 2>/dev/null || echo 0)"
    wait "$rx" || true
    local got
    got="$(cat "$rx_out")"
    rm -f "$rx_out"
    echo "  probes sent by the attacker: $sent"
    echo "  probes the victim received: ${got:-0}"
    SENT_COUNT="$sent"
    RECEIVED_COUNT="${got:-0}"
}

echo "Phase 1: control, probes sent straight to the victim's MAC (both ports isolated)"
run_phase ""
CONTROL_RECEIVED="$RECEIVED_COUNT"
CONTROL_SENT="$SENT_COUNT"
echo

echo "Phase 2: bypass, probes sent to the promiscuous relay, which forwards them to the victim"
run_phase "$RELAY_MAC"
BYPASS_RECEIVED="$RECEIVED_COUNT"
BYPASS_SENT="$SENT_COUNT"
echo

if [[ "$CONTROL_SENT" == "$PROBES" && "$BYPASS_SENT" == "$PROBES" && "$CONTROL_RECEIVED" == "0" && "$BYPASS_RECEIVED" -ge 1 ]]; then
    echo "Result: with both ports isolated, the victim received none of the $PROBES direct probes. Through the promiscuous relay it received $BYPASS_RECEIVED of $PROBES. The isolation holds between the isolated ports but not against a promiscuous device that forwards. The relay's own filters and the target switch's private VLAN setup are not tested here."
    exit 0
elif [[ "$CONTROL_SENT" != "$PROBES" || "$BYPASS_SENT" != "$PROBES" ]]; then
    echo "Result: inconclusive. The attacker did not send the probes. Result unreliable."
    exit 2
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
