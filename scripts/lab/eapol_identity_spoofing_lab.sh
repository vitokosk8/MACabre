#!/usr/bin/env bash
# Isolated 802.1X identity spoofing lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with two hosts attached:
#
#   auth:     FreeRADIUS (local, 127.0.0.1:1812) and hostapd in wired mode, the 802.1X
#             authenticator on h-auth. FreeRADIUS knows one user, alice, with a password.
#   attacker: MACabre's identity spoofing from the attacker's MAC. It claims identities without
#             any proof: bob (unknown to RADIUS) and alice (known, but no password is sent).
#
# Each identity is claimed from its own random MAC. FreeRADIUS answers an unknown or
# password-less user with an EAP-MD5 challenge that stays open until a response, and
# hostapd ignores a second identity from the same MAC while that exchange is open.
#
# Phases:
#   Phase 1 (control): one EAPOL-Start from the attacker's MAC, and no identity answer. The
#            authenticator asks for the identity and waits. No RADIUS request must follow.
#   Phase 2 (attack): MACabre's module starts an exchange for each identity and answers the
#            identity request with that name. The lab counts the RADIUS Access-Requests whose
#            User-Name is each claimed identity.
#
# What the lab shows: whether the authenticator forwards each unverified identity to the
# authentication server, which then decides. Forwarding is the standard behavior, so the
# result describes what RADIUS receives and decides, not a failure of the authenticator.
# A RADIUS policy that accepts a name without a credential (for example MAC-based or
# fallback authentication) is not tested here.
#
# Requirements: FreeRADIUS with IPv4 listeners only, and the test user alice in its authorize
# file (see the EAPOL logoff spoofing lab). Nothing here touches the host's real interfaces.
#
# Usage:
#   sudo scripts/lab/eapol_identity_spoofing_lab.sh
#
# Requirements: iproute2, hostapd, freeradius, and the project virtualenv (.venv).
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
FREERADIUS="$(command -v freeradius 2>/dev/null || echo /usr/sbin/freeradius)"
for tool in "$HOSTAPD" "$FREERADIUS"; do
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
ATTACKER_MAC="02:00:00:00:00:71"
IDENTITIES="bob,alice"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in auth attacker; do
        for pid in $(ip netns pids "$ns" 2>/dev/null || true); do
            kill "$pid" 2>/dev/null || true
        done
    done
    for ns in attacker auth lan; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
cleanup() {
    stop_lab
    if [[ -n "${KEEP_LOGS:-}" ]]; then
        echo "logs kept in $WORK" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

stop_lab

ip netns add lan
ip netns add auth
ip netns add attacker

for pair in "auth:auth" "att:attacker"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

# group_fwd_mask 8 lets the bridge forward the 802.1X PAE group address.
ip netns exec lan ip link add br0 type bridge group_fwd_mask 8
ip netns exec lan ip link set br0 up
for name in auth att; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec auth ip link set lo up
ip netns exec auth ip link set h-auth up
ip netns exec attacker ip link set lo up
ip netns exec attacker ip link set h-att address "$ATTACKER_MAC"
ip netns exec attacker ip link set h-att up

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

ATTACK_CODE='
import os, threading
from macabre.attacks.eapol_identity_spoofing import EapolIdentitySpoofingConfig, run_eapol_identity_spoofing
stats = run_eapol_identity_spoofing(
    EapolIdentitySpoofingConfig(
        iface="h-att",
        identities=tuple(os.environ["IDENTITIES"].split(",")),
        response_timeout=3.0,
    ),
    threading.Event(),
    lambda _: None,
)
print(f"{stats.exchanges} {stats.requests_seen} {stats.responses}")
'

START_CODE='
import os, threading
from macabre.attacks.eapol_start_flooding import EapolStartFloodingConfig, run_eapol_start_flooding
stats = run_eapol_start_flooding(
    EapolStartFloodingConfig(iface="h-att", frames=1, source_mac=os.environ["ATTACKER_MAC"]),
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
    tail -10 "$WORK/radius.log" >&2
    tail -10 "$WORK/hostapd.log" >&2
    exit 2
fi

user_requests() {
    grep -c -E "^\([0-9]+\)[[:space:]]+User-Name = \"$1\"" "$WORK/radius.log" 2>/dev/null || true
}
rejects() {
    grep -c "Sent Access-Reject" "$WORK/radius.log" 2>/dev/null || true
}
challenges() {
    grep -c "Sent Access-Challenge" "$WORK/radius.log" 2>/dev/null || true
}
accepts() {
    grep -c "Sent Access-Accept" "$WORK/radius.log" 2>/dev/null || true
}

echo "Phase 1: control, one EAPOL-Start from the attacker's MAC, no identity answer"
BEFORE_BOB=$(user_requests bob)
BEFORE_ALICE=$(user_requests alice)
ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" "$PY" -c "$START_CODE" >/dev/null 2>&1 || true
sleep 5
CONTROL_BOB=$(( $(user_requests bob) - BEFORE_BOB ))
CONTROL_ALICE=$(( $(user_requests alice) - BEFORE_ALICE ))
echo "  RADIUS requests for bob: $CONTROL_BOB, for alice: $CONTROL_ALICE"
echo

echo "Phase 2: attack, claim $IDENTITIES with no proof"
BEFORE_BOB=$(user_requests bob)
BEFORE_ALICE=$(user_requests alice)
BEFORE_REJECTS=$(rejects)
BEFORE_CHALLENGES=$(challenges)
BEFORE_ACCEPTS=$(accepts)
ATTACK_RESULT="$(ip netns exec attacker env PYTHONPATH="$ROOT/src" ATTACKER_MAC="$ATTACKER_MAC" IDENTITIES="$IDENTITIES" \
    "$PY" -c "$ATTACK_CODE" 2>/dev/null || echo "0 0 0")"
sleep 6
read -r EXCHANGES REQUESTS_SEEN RESPONSES <<<"$ATTACK_RESULT"
ATTACK_BOB=$(( $(user_requests bob) - BEFORE_BOB ))
ATTACK_ALICE=$(( $(user_requests alice) - BEFORE_ALICE ))
ATTACK_REJECTS=$(( $(rejects) - BEFORE_REJECTS ))
ATTACK_CHALLENGES=$(( $(challenges) - BEFORE_CHALLENGES ))
ATTACK_ACCEPTS=$(( $(accepts) - BEFORE_ACCEPTS ))
echo "  exchanges: $EXCHANGES, identity requests seen: $REQUESTS_SEEN, identities answered: $RESPONSES"
echo "  RADIUS requests for bob: $ATTACK_BOB, for alice: $ATTACK_ALICE"
echo "  RADIUS Access-Challenge sent: $ATTACK_CHALLENGES"
echo "  RADIUS Access-Accept sent: $ATTACK_ACCEPTS"
echo "  RADIUS Access-Reject sent: $ATTACK_REJECTS"
echo

if (( CONTROL_BOB != 0 || CONTROL_ALICE != 0 )); then
    echo "Control: RADIUS received an identity without one being claimed. Result unreliable."
    exit 2
fi
if (( RESPONSES == 2 && ATTACK_BOB >= 1 && ATTACK_ALICE >= 1 )); then
    echo "Result: the authenticator forwarded both claimed identities to RADIUS without any proof (bob: $ATTACK_BOB request(s), alice: $ATTACK_ALICE request(s)). RADIUS answered with $ATTACK_CHALLENGES EAP-MD5 challenge(s) and $ATTACK_ACCEPTS Access-Accept, so no session was granted. The name is passed on before any credential is checked."
    exit 0
fi
echo "Result: the claimed identities did not all reach RADIUS in this run ($ATTACK_BOB for bob, $ATTACK_ALICE for alice). Result unreliable."
exit 1
