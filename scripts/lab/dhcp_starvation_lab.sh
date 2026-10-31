#!/usr/bin/env bash
# Isolated DHCP starvation lab (Linux only, needs root).
#
# Builds two network namespaces joined by a veth pair:
#   - "server":   dnsmasq acting as a DHCP server (pool of 20 addresses)
#   - "attacker": MACabre's DHCP starvation sending frames on the veth
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

ip netns exec server dnsmasq \
    --keep-in-foreground \
    --interface=vs \
    --bind-interfaces \
    --port=0 \
    --conf-file=/dev/null \
    --dhcp-authoritative \
    --dhcp-range=10.99.0.100,10.99.0.119,12h \
    --dhcp-leasefile="$LEASES" \
    --log-dhcp \
    --log-facility="$LOG" &
sleep 2

echo "Sending $FRAMES DHCPDISCOVER frames from the attacker namespace..."
ip netns exec attacker env PYTHONPATH="$ROOT/src" "$PY" -c "
import os, threading
from macabre.attacks.dhcp_starvation import DhcpStarvationConfig, run_starvation
count = int(os.environ['FRAMES'])
sent = run_starvation(
    DhcpStarvationConfig(iface='va', count=count, interval=0.01),
    threading.Event(),
    lambda _: None,
)
print(f'Frames sent: {sent}')
"

count_discovers() {
    local n
    n=$(grep -c 'DHCPDISCOVER' "$LOG" 2>/dev/null || true)
    echo "${n:-0}"
}

# dnsmasq writes its log with some delay, so wait until the count stops
# changing (or reaches the number of frames sent).
wait_for_server() {
    local previous=-1 current stable=0
    for _ in $(seq 1 60); do
        current=$(count_discovers)
        if [[ "$current" -ge "$FRAMES" ]]; then
            break
        fi
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

wait_for_server

discovers=$(count_discovers)
offers=$(grep -c 'DHCPOFFER' "$LOG" || true)
distinct=$(grep -o 'DHCPOFFER(vs) 10\.99\.0\.[0-9]*' "$LOG" | sort -u | wc -l)
requests=$(grep -c 'DHCPREQUEST' "$LOG" || true)
leases_stored=$(wc -l < "$LEASES" 2>/dev/null || echo 0)

echo
echo "Server results (dnsmasq):"
echo "  DISCOVER received:       $discovers"
echo "  OFFER sent:              $offers"
echo "  distinct addresses:      $distinct of 20"
echo "  REQUEST received:        $requests"
echo "  leases stored:           $leases_stored"
echo
echo "Note: without DHCPREQUEST, dnsmasq does not record leases, so the pool"
echo "is not exhausted. Full starvation needs answering each OFFER (planned)."
