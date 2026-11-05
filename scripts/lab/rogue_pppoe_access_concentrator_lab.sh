#!/usr/bin/env bash
# Isolated rogue PPPoE access concentrator lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   server:   pppoe-server (rp-pppoe), the legitimate access concentrator (10.10.0.1).
#   attacker: MACabre's rogue concentrator, answering PADI with PADO and matching PADR with PADS.
#   client:   a probe client. It sends a PADI, collects the PADOs, sends a PADR to the one it
#             picks, and records which concentrator sent the PADS.
#
# The lab runs three phases, because they answer different questions:
#
#   Phase 1 (control): no rogue. The client takes the first PADO. The legitimate server answers.
#   Phase 2 (race): the rogue runs. The client still takes the first PADO that arrives. The lab
#            counts how often the rogue's PADO is first. This measures the race on this host.
#   Phase 3 (handshake): the rogue runs. The client takes the rogue's PADO, whichever arrives
#            first, and sends its PADR with the AC-Cookie. The lab counts the PADS the rogue
#            sends back. This checks that the rogue completes the exchange when a client
#            chooses it.
#
# Each trial uses a new client MAC, so the concentrators keep no state between trials.
#
# What the lab shows: whether the rogue answers a PADI, and whether it completes PADR/PADS for
# a client that chose it. It also reports how often the rogue wins the first-PADO race on this
# host; that race depends on timing and is not forced. It does not test PAP or CHAP credential
# capture (no PPP runs here), and it does not test vendor concentrators or how their clients choose.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/rogue_pppoe_access_concentrator_lab.sh
#   sudo TRIALS=20 scripts/lab/rogue_pppoe_access_concentrator_lab.sh
#
# Requirements: iproute2, rp-pppoe (pppoe-server), and the project virtualenv (.venv).
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
PPPOE_SERVER="$(command -v pppoe-server 2>/dev/null || echo /usr/sbin/pppoe-server)"
if [[ ! -x "$PPPOE_SERVER" ]]; then
    echo "Missing required tool: pppoe-server (install the rp-pppoe package)" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
TRIALS="${TRIALS:-10}"
ROGUE_MAC="02:00:00:00:00:44"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in server attacker client; do
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
ip netns exec attacker ip link set h-att address "$ROGUE_MAC"
ip netns exec attacker ip link set h-att up
ip netns exec client ip link set lo up
ip netns exec client ip link set h-cli up

LEGIT_MAC="$(ip netns exec server cat /sys/class/net/h-srv/address)"

ip netns exec server "$PPPOE_SERVER" \
    -I h-srv -L 10.10.0.1 -R 10.10.0.100 -N 3 -F >"$WORK/server.log" 2>&1 &
sleep 3

# One trial. PICK=first takes the first PADO; PICK=rogue takes the PADO from ROGUE_MAC.
# Prints "<chosen PADO source> <PADS source or none>".
TRIAL_CODE='
import os, time
from scapy.all import AsyncSniffer, Ether, sendp
from scapy.layers.ppp import PPPoED, PPPoED_Tags, PPPoETag
mac = os.environ["PROBE_MAC"]
pick = os.environ["PICK"]
rogue = os.environ["ROGUE_MAC"]
seen = []
sniffer = AsyncSniffer(
    iface="h-cli", promisc=True,
    lfilter=lambda p: p.haslayer(PPPoED) and p[PPPoED].code in (0x07, 0x65) and p[Ether].dst == mac,
    prn=seen.append,
    store=False,
)
sniffer.start()
time.sleep(0.3)
sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff", type=0x8863) / PPPoED(code=0x09, sessionid=0),
      iface="h-cli", verbose=False)
time.sleep(1.0)
pados = [p for p in seen if p[PPPoED].code == 0x07]
if pick == "rogue":
    pados = [p for p in pados if p[Ether].src == rogue]
if not pados:
    sniffer.stop()
    print("none none")
    raise SystemExit
chosen = pados[0]
tags = [PPPoETag(tag_type=t.tag_type, tag_value=t.tag_value) for t in chosen[PPPoED_Tags].tag_list if t.tag_type in (0x0101, 0x0104)]
sendp(Ether(src=mac, dst=chosen[Ether].src, type=0x8863) / PPPoED(code=0x19, sessionid=0) / PPPoED_Tags(tag_list=tags),
      iface="h-cli", verbose=False)
time.sleep(1.0)
sniffer.stop()
pads = [p for p in seen if p[PPPoED].code == 0x65]
print(chosen[Ether].src, pads[0][Ether].src if pads else "none")
'

ROGUE_CODE='
import os, signal, threading
from macabre.attacks.rogue_pppoe_access_concentrator import RoguePppoeAcConfig, run_rogue_pppoe_ac
stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
threading.Timer(float(os.environ["ROGUE_SECONDS"]), stop.set).start()
stats = run_rogue_pppoe_ac(RoguePppoeAcConfig(iface="h-att", ac_mac=os.environ["ROGUE_MAC"]), stop, lambda _: None)
print(f"padi={stats.padi} pado={stats.pado} padr={stats.padr} pads={stats.pads}")
'

# Runs TRIALS trials with the given pick mode. Sets RUN_ROGUE_PADS, RUN_LEGIT_PADS and RUN_NONE.
run_trials() {
    local pick="$1" rogue_pads=0 legit_pads=0 none=0 i mac chosen pads
    for i in $(seq 1 "$TRIALS"); do
        mac=$(printf "02:00:00:00:02:%02x" "$i")
        read -r chosen pads < <(ip netns exec client env PYTHONPATH="$ROOT/src" PROBE_MAC="$mac" \
            PICK="$pick" ROGUE_MAC="$ROGUE_MAC" "$PY" -c "$TRIAL_CODE" 2>/dev/null || echo "none none")
        if [[ "$chosen" == "none" ]]; then
            none=$((none + 1))
        elif [[ "$pads" == "$ROGUE_MAC" ]]; then
            rogue_pads=$((rogue_pads + 1))
        elif [[ "$pads" == "$LEGIT_MAC" ]]; then
            legit_pads=$((legit_pads + 1))
        fi
    done
    RUN_ROGUE_PADS=$rogue_pads
    RUN_LEGIT_PADS=$legit_pads
    RUN_NONE=$none
}

echo "Phase 1: control, the legitimate server only, the client takes the first PADO"
run_trials first
CONTROL_LEGIT=$RUN_LEGIT_PADS
CONTROL_ROGUE=$RUN_ROGUE_PADS
echo "  PADS from the legitimate server in $CONTROL_LEGIT of $TRIALS trials; from the rogue in $CONTROL_ROGUE; no PADO in $RUN_NONE"
echo

ROGUE_SECONDS=$(( TRIALS * 8 + 20 ))
ip netns exec attacker env PYTHONPATH="$ROOT/src" ROGUE_MAC="$ROGUE_MAC" ROGUE_SECONDS="$ROGUE_SECONDS" \
    "$PY" -c "$ROGUE_CODE" >"$WORK/rogue.log" 2>&1 &
ROGUE_PID=$!
sleep 2

echo "Phase 2: race, the rogue running, the client takes the first PADO"
run_trials first
RACE_ROGUE=$RUN_ROGUE_PADS
RACE_LEGIT=$RUN_LEGIT_PADS
echo "  PADS from the rogue in $RACE_ROGUE of $TRIALS trials; from the legitimate server in $RACE_LEGIT"
echo

echo "Phase 3: handshake, the rogue running, the client takes the rogue's PADO"
run_trials rogue
HANDSHAKE_ROGUE=$RUN_ROGUE_PADS
HANDSHAKE_LEGIT=$RUN_LEGIT_PADS
echo "  PADS from the rogue in $HANDSHAKE_ROGUE of $TRIALS trials; from the legitimate server in $HANDSHAKE_LEGIT"
echo

kill -TERM "$ROGUE_PID" 2>/dev/null || true
wait "$ROGUE_PID" 2>/dev/null || true
echo "  rogue concentrator counters: $(tail -1 "$WORK/rogue.log" 2>/dev/null)"
echo

if (( CONTROL_ROGUE != 0 )); then
    echo "Control: the rogue answered a client without running. Result unreliable."
    exit 2
fi
if (( CONTROL_LEGIT == 0 )); then
    echo "Control: the legitimate server did not complete a session. Result unreliable."
    exit 2
fi
if (( HANDSHAKE_ROGUE * 100 >= TRIALS * 90 )); then
    echo "Handshake: the rogue completed PADR/PADS with a client that chose it in $HANDSHAKE_ROGUE of $TRIALS trials (at least 90%)."
    echo "Race: the rogue's PADO came first in $RACE_ROGUE of $TRIALS trials on this host. The legitimate server answered first in the other trials."
    echo "Result: a client that chooses the rogue's PADO completes the session with it. Whether a client picks the rogue first depends on timing and on the legitimate concentrator's response."
    exit 0
fi
echo "Handshake: the rogue completed PADR/PADS in only $HANDSHAKE_ROGUE of $TRIALS trials. Result unreliable."
exit 1
