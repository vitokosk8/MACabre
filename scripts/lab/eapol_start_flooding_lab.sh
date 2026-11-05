#!/usr/bin/env bash
# Isolated EAPOL start flooding lab (Linux only, needs root).
#
# Topology: one bridge (the LAN) with three hosts attached:
#
#   auth:     hostapd in wired mode, the 802.1X authenticator on h-auth. There is no RADIUS
#             server: the lab counts the identity requests, and does not complete authentication.
#   attacker: MACabre's EAPOL-Start flood, from random supplicant MACs.
#   client:   a probe supplicant. It sends one EAPOL-Start with its own MAC and counts the
#             EAP-Request/Identity frames sent back to that MAC.
#
#   Phase 1 (baseline): one probe. The authenticator should send an identity request to it.
#   Phase 2 (flood): the attacker sends FRAMES EAPOL-Start frames from random MACs. Its
#            interface is promiscuous and counts the identity requests the authenticator sends
#            back. Each request is unicast to a random MAC, which the bridge learned on the
#            attacker's port.
#   Phase 3 (after): one probe, to see whether the authenticator still answers a supplicant.
#
# What the lab shows: whether the authenticator answers each EAPOL-Start in a flood with an
# identity request, and whether a legitimate supplicant still gets one afterwards. It does not
# show how much state or memory hostapd uses, nor the behavior of vendor authenticators or
# their limits on sessions per port. The bridge forwards the PAE group address (group_fwd_mask 8),
# which Linux bridges otherwise drop.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/eapol_start_flooding_lab.sh
#   sudo FRAMES=500 scripts/lab/eapol_start_flooding_lab.sh
#
# Requirements: iproute2, hostapd, and the project virtualenv (.venv).
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
if [[ ! -x "$HOSTAPD" ]]; then
    echo "Missing required tool: hostapd" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
FRAMES="${FRAMES:-200}"
PROBE_MAC="02:00:00:00:00:61"
WORK="$(mktemp -d)"

stop_lab() {
    for ns in auth attacker client; do
        for pid in $(ip netns pids "$ns" 2>/dev/null || true); do
            kill "$pid" 2>/dev/null || true
        done
    done
    for ns in client attacker auth lan; do
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
ip netns add attacker
ip netns add client

for pair in "auth:auth" "att:attacker" "cli:client"; do
    name="${pair%%:*}"
    ns="${pair##*:}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$ns"
    ip link set "p-$name" netns lan
done

# group_fwd_mask 8 lets the bridge forward the 802.1X PAE group address (01:80:c2:00:00:03).
ip netns exec lan ip link add br0 type bridge group_fwd_mask 8
ip netns exec lan ip link set br0 up
for name in auth att cli; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done

ip netns exec auth ip link set lo up
ip netns exec auth ip link set h-auth up
ip netns exec attacker ip link set lo up
ip netns exec attacker ip link set h-att up
ip netns exec client ip link set lo up
ip netns exec client ip link set h-cli up

cat >"$WORK/hostapd.conf" <<EOF
driver=wired
interface=h-auth
logger_stdout=-1
logger_stdout_level=2
ieee8021x=1
eap_reauth_period=3600
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=macabre-lab
EOF

ip netns exec auth "$HOSTAPD" "$WORK/hostapd.conf" >"$WORK/hostapd.log" 2>&1 &
sleep 3
if [[ -z "$(ip netns pids auth 2>/dev/null)" ]]; then
    echo "hostapd did not start. Log:" >&2
    tail -20 "$WORK/hostapd.log" >&2
    exit 2
fi

# One probe: send an EAPOL-Start from PROBE_MAC, print how many identity requests came back to it.
PROBE_CODE='
import os, time
from scapy.all import AsyncSniffer, Ether, sendp
from scapy.layers.eap import EAP, EAPOL
mac = os.environ["PROBE_MAC"]
seen = []
sniffer = AsyncSniffer(
    iface="h-cli", promisc=True,
    lfilter=lambda p: p.haslayer(EAP) and p[EAP].code == 1 and p[Ether].dst == mac,
    prn=seen.append,
    store=False,
)
sniffer.start()
time.sleep(0.3)
sendp(Ether(src=mac, dst="01:80:c2:00:00:03", type=0x888E) / EAPOL(version=2, type=1), iface="h-cli", verbose=False)
time.sleep(2)
sniffer.stop()
print(len(seen))
'

FLOOD_CODE='
import os, time, threading
from scapy.all import AsyncSniffer, Ether
from scapy.layers.eap import EAP
from macabre.attacks.eapol_start_flooding import EapolStartFloodingConfig, run_eapol_start_flooding
frames = int(os.environ["FRAMES"])
replies = []
sniffer = AsyncSniffer(
    iface="h-att", promisc=True,
    lfilter=lambda p: p.haslayer(EAP) and p[EAP].code == 1,
    prn=replies.append,
    store=False,
)
sniffer.start()
time.sleep(0.3)
stats = run_eapol_start_flooding(
    EapolStartFloodingConfig(iface="h-att", frames=frames),
    threading.Event(),
    lambda _: None,
)
time.sleep(2)
sniffer.stop()
print(f"{stats.frames} {len({p[Ether].dst for p in replies})} {len(replies)}")
'

probe() {
    ip netns exec client env PYTHONPATH="$ROOT/src" PROBE_MAC="$PROBE_MAC" "$PY" -c "$PROBE_CODE" 2>/dev/null || echo 0
}

echo "Phase 1: baseline probe"
BASE_REQUESTS="$(probe)"
echo "  identity requests to the probe: $BASE_REQUESTS"
echo

echo "Phase 2: flood $FRAMES EAPOL-Start frames from random supplicant MACs"
read -r SENT ANSWERED TOTAL < <(ip netns exec attacker env PYTHONPATH="$ROOT/src" FRAMES="$FRAMES" \
    "$PY" -c "$FLOOD_CODE" 2>/dev/null || echo "0 0 0")
echo "  EAPOL-Start frames sent by MACabre: $SENT"
echo "  supplicants that got an identity request: $ANSWERED"
echo "  identity requests seen in total, including retransmissions: $TOTAL"
echo

echo "Phase 3: probe after the flood"
AFTER_REQUESTS="$(probe)"
echo "  identity requests to the probe: $AFTER_REQUESTS"
echo

if (( BASE_REQUESTS > 0 )); then
    echo "Baseline: the authenticator answered the probe's EAPOL-Start with an identity request. OK"
else
    echo "Baseline: no identity request before the flood. Result unreliable."
    exit 2
fi

if (( SENT > 0 && ANSWERED * 100 >= SENT * 90 )); then
    echo "Delivery: the authenticator answered $ANSWERED of $SENT EAPOL-Start supplicants (at least 90%)."
    DELIVERED=1
else
    echo "Delivery: the authenticator answered only $ANSWERED of $SENT EAPOL-Start supplicants."
    DELIVERED=0
fi

if (( AFTER_REQUESTS > 0 )); then
    echo "After the flood: the probe still got an identity request. The flood did not stop the authenticator from answering."
else
    echo "After the flood: the probe got no identity request."
fi

echo
echo "Result: the authenticator answered $ANSWERED of $SENT supplicants that sent EAPOL-Start, with $TOTAL identity requests in total. Authenticator state and limits are not measured here."
if (( DELIVERED == 1 && AFTER_REQUESTS > 0 )); then
    exit 0
fi
exit 1
