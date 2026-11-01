#!/usr/bin/env bash
# Isolated MAC cloning lab (Linux only, needs root).
#
# Topology, all inside network namespaces, one Linux bridge as the switch:
#
#   attacker --(veth)-- [switch: br0, port sw-a] --(veth)-- server
#
# The switch port sw-a works like port security with a single allowed MAC:
# an nftables bridge rule drops every frame from attacker's port whose source
# MAC is not AUTH_MAC. AUTH_MAC is the address of an authorized device; only its
# address matters in this lab.
#
#   Phase 1: the attacker sends with its own MAC. The switch drops the frames.
#   Phase 2: MACabre's MAC cloning changes the attacker's interface to AUTH_MAC.
#            The host now sends with that identity, the rule accepts the frames,
#            and the server receives them. The original MAC is restored at the end.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/mac_cloning_lab.sh
#   sudo FRAMES=100 scripts/lab/mac_cloning_lab.sh
#
# Requirements: iproute2 (ip, bridge), nft (nftables), and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge nft; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-20}"
SNIFF_SECONDS=8
AUTH_MAC="02:00:00:00:00:20"
ATTACKER_MAC="02:00:00:00:00:30"
SERVER_MAC="02:00:00:00:00:40"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in server attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

# Remove leftovers from a previous interrupted run.
stop_lab

ip netns add switch
ip netns add attacker
ip netns add server

# attacker <-> switch port sw-a
ip link add a-sw type veth peer name sw-a
ip link set a-sw netns attacker
ip link set sw-a netns switch

# server <-> switch port sw-srv
ip link add srv-sw type veth peer name sw-srv
ip link set srv-sw netns server
ip link set sw-srv netns switch

ip netns exec switch ip link add br0 type bridge
ip netns exec switch ip link set br0 up
for port in sw-a sw-srv; do
    ip netns exec switch ip link set "$port" master br0
    ip netns exec switch ip link set "$port" up
done

ip netns exec attacker ip link set a-sw address "$ATTACKER_MAC"
ip netns exec attacker ip link set a-sw up
ip netns exec server ip link set srv-sw address "$SERVER_MAC"
ip netns exec server ip link set srv-sw up

# Port security emulation: only AUTH_MAC may send from the attacker's port.
cat > "$WORK/portsec.nft" <<EOF
table bridge portsec {
    chain input {
        type filter hook prerouting priority -300; policy accept;
        iifname "sw-a" ether saddr != $AUTH_MAC drop
    }
}
EOF
ip netns exec switch nft -f "$WORK/portsec.nft"

SNIFFER_CODE='
import os
from scapy.all import Ether, sniff
count = 0
def cb(pkt):
    global count
    if Ether in pkt and pkt[Ether].dst == os.environ["SERVER_MAC"] and pkt[Ether].type == 0x88B5:
        count += 1
sniff(iface="srv-sw", prn=cb, timeout=int(os.environ["SNIFF_SECONDS"]), store=False)
open(os.environ["OUT"], "w").write(str(count))
'

start_server_sniffer() {
    local out="$1"
    ip netns exec server env PYTHONPATH="$ROOT/src" SERVER_MAC="$SERVER_MAC" \
        SNIFF_SECONDS="$SNIFF_SECONDS" OUT="$out" "$PY" -c "$SNIFFER_CODE" &
}

# Sends FRAMES frames from the attacker with the MAC the host currently has.
SEND_PLAIN_CODE='
import os
from scapy.all import Ether, Raw, sendp

# Scapy caches interface MACs when it loads, so read the current address with ip.
def host_mac():
    import re, subprocess
    out = subprocess.run(["ip", "-o", "link", "show", "dev", "a-sw"],
                         capture_output=True, text=True, check=True).stdout
    return re.search(r"link/ether ([0-9a-f:]{17})", out).group(1)
src = host_mac()
sendp(Ether(src=src, dst=os.environ["SERVER_MAC"], type=0x88B5) / Raw(b"x" * 46),
      iface="a-sw", count=int(os.environ["COUNT"]), verbose=False)
count = os.environ["COUNT"]
print("Attacker: sent " + count + " frames with source " + src)
'

# Phase 2: clone AUTH_MAC for the duration of the sending, then stop and restore.
CLONE_CODE='
import os, threading, time
from scapy.all import Ether, Raw, sendp
from macabre.attacks.mac_cloning import MacCloningConfig, run_cloning

# Scapy caches interface MACs when it loads, so read the current address with ip.
def host_mac():
    import re, subprocess
    out = subprocess.run(["ip", "-o", "link", "show", "dev", "a-sw"],
                         capture_output=True, text=True, check=True).stdout
    return re.search(r"link/ether ([0-9a-f:]{17})", out).group(1)

stop = threading.Event()
progress = []
worker = threading.Thread(
    target=run_cloning,
    args=(MacCloningConfig(iface="a-sw", target_mac=os.environ["AUTH_MAC"]), stop, progress.append),
)
worker.start()
time.sleep(2)
src = host_mac()
print(f"Host MAC while cloned: {src}")
sendp(Ether(src=src, dst=os.environ["SERVER_MAC"], type=0x88B5) / Raw(b"x" * 46),
      iface="a-sw", count=int(os.environ["COUNT"]), verbose=False)
time.sleep(1)
stop.set()
worker.join()
print(f"Attacker: {progress[-1].status}")
'

# --- Phase 1: no clone, the switch must drop the frames --------------------

echo "Phase 1: $FRAMES frames from the attacker's own MAC ($ATTACKER_MAC)"
start_server_sniffer "$WORK/server_1"
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" SERVER_MAC="$SERVER_MAC" COUNT="$FRAMES" \
    "$PY" -c "$SEND_PLAIN_CODE"
wait
echo "  received by server: $(cat "$WORK/server_1") of $FRAMES"
echo

# --- Phase 2: MAC cloning of AUTH_MAC ---------------------------------------

echo "Phase 2: MACabre clones $AUTH_MAC on the attacker, then sends $FRAMES frames"
start_server_sniffer "$WORK/server_2"
sleep 2
ip netns exec attacker env PYTHONPATH="$ROOT/src" AUTH_MAC="$AUTH_MAC" SERVER_MAC="$SERVER_MAC" \
    COUNT="$FRAMES" "$PY" -c "$CLONE_CODE"
wait
echo "  received by server: $(cat "$WORK/server_2") of $FRAMES"
echo "  attacker MAC after stop: $(ip netns exec attacker ip -o link show dev a-sw | grep -oE 'link/ether [0-9a-f:]{17}' | cut -d' ' -f2)"
echo
echo "Expected: phase 1 drops all frames; phase 2 delivers them, and the attacker's"
echo "MAC returns to $ATTACKER_MAC when the clone stops."
