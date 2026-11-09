#!/usr/bin/env bash
# Isolated Router Solicitation flooding lab (Linux only, needs root and IPv6 in the kernel).
#
# Topology, all inside network namespaces, two nodes on one link:
#
#   router:   a Linux host with IPv6 forwarding on. It is the router whose solicitation load is measured.
#   attacker: sends Router Solicitations through MACabre's module.
#
# Measure: the router's Icmp6InRouterSolicits counter in /proc/net/snmp6. The kernel increments it for
# every RS it receives, before deciding whether to answer, so the counter is the load the flood puts on
# the router.
#
# Phases:
#   control: no attacker. The counter must stay near zero over the window.
#   attack:  the attacker sends FRAMES RSs. The counter must rise by at least 90% of FRAMES.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/router_solicitation_flooding_lab.sh
#
# Exit 0 when control stays quiet and attack raises the counter by at least 90% of FRAMES.
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
ROUTER_MAC="02:00:00:00:00:10"
ATTACKER_MAC="02:00:00:00:00:30"
FRAMES="${FRAMES:-500}"
INTERVAL="${INTERVAL:-0.005}"
WINDOW="${WINDOW:-3}"                 # seconds the control waits and the attack keeps the counter open
ROUTER_ADDR="2001:db8:1::1"

stop_lab() {
    for ns in attacker router; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

build_topology() {
    stop_lab
    for ns in router attacker; do
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
    done
    ip link add r0 type veth peer name a1
    ip link set r0 netns router
    ip link set a1 netns attacker
    ip netns exec router ip link set r0 address "$ROUTER_MAC"
    ip netns exec attacker ip link set a1 address "$ATTACKER_MAC"
    ip netns exec router ip link set r0 up
    ip netns exec attacker ip link set a1 up
    ip netns exec router ip -6 addr add "$ROUTER_ADDR/64" dev r0 nodad
    ip netns exec router sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
}

rs_count() {
    ip netns exec router awk '$1=="Icmp6InRouterSolicits" {print $2}' /proc/net/snmp6
}

echo "=== control ==="
build_topology
before=$(rs_count)
sleep "$WINDOW"
after=$(rs_count)
control_delta=$((after - before))
echo "Router Solicitations received over ${WINDOW} s: $control_delta"

echo "=== attack ==="
build_topology
before=$(rs_count)
ip netns exec attacker "$PY" -m macabre.attacks.router_solicitation_flooding a1 \
    --source-mac "$ATTACKER_MAC" --frames "$FRAMES" --interval "$INTERVAL"
sleep 1
after=$(rs_count)
attack_delta=$((after - before))
echo "Router Solicitations received during the attack: $attack_delta of $FRAMES sent"

echo
threshold=$(( FRAMES * 9 / 10 ))
control_ok=0; attack_ok=0
if (( control_delta < 5 )); then control_ok=1; fi
if (( attack_delta >= threshold )); then attack_ok=1; fi
echo "control: the router stays quiet (< 5): $([[ $control_ok == 1 ]] && echo yes || echo no)"
echo "attack:  the router receives at least $threshold solicitations: $([[ $attack_ok == 1 ]] && echo yes || echo no)"

if (( control_ok && attack_ok )); then
    echo "PASS: the flood delivers its Router Solicitations to the router."
    exit 0
fi
echo "FAIL: the router's solicitation counter did not change as expected."
exit 1
