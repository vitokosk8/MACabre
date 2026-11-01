#!/usr/bin/env bash
# Isolated DTP negotiation audit lab (Linux only, needs root).
#
# Topology, all inside network namespaces:
#
#   attacker --(veth att0 <-> sw0)-- switch
#
#   switch:   a simulated access-side port (no real switch is involved). It advertises its
#             DTP status and answers any DTP negotiation frame with the same status. The
#             status is 0x03 (trunk) in phase 1 and 0x04 (access) in phase 2.
#   attacker: MACabre's DTP audit, which listens on att0 and sends one negotiation probe.
#
# What this lab shows: the audit decodes the status and encapsulation the port advertises,
# and its verdict matches the simulated mode. Real Cisco ports are not simulated here, and
# the status values are read from the public DTP description, not checked on a switch.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dtp_audit_lab.sh
#   sudo LISTEN_SECONDS=5 scripts/lab/dtp_audit_lab.sh
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
LISTEN_SECONDS="${LISTEN_SECONDS:-4}"

stop_lab() {
    for ns in attacker switch; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

stop_lab

ip netns add switch
ip netns add attacker

ip link add att0 type veth peer name sw0
ip link set att0 netns attacker
ip link set sw0 netns switch
ip netns exec attacker ip link set att0 up
ip netns exec switch ip link set sw0 up

# The simulated port: answers DTP negotiation with the status for its mode.
PORT_CODE='
import os, threading
from scapy.all import AsyncSniffer, Dot3, Ether, Raw, sendp
from macabre.attacks.switch_spoofing import DTP_MAC, SNAP_HEADER, TLV_DOMAIN, TLV_NEIGHBOR, TLV_STATUS, TLV_TYPE
from macabre.attacks.dtp_audit import parse_dtp, STATUS_TRUNK, STATUS_ACCESS, TYPE_DOT1Q
mode = os.environ["MODE"]
status = STATUS_TRUNK if mode == "trunk" else STATUS_ACCESS
with open("/sys/class/net/sw0/address") as handle:
    own = handle.read().strip()
own_bytes = bytes.fromhex(own.replace(":", ""))

def tlv(kind, value):
    return kind.to_bytes(2, "big") + (4 + len(value)).to_bytes(2, "big") + value

def advertisement():
    body = tlv(TLV_DOMAIN, b"ops") + tlv(TLV_STATUS, bytes([status])) + tlv(TLV_TYPE, bytes([TYPE_DOT1Q])) + tlv(TLV_NEIGHBOR, own_bytes)
    payload = SNAP_HEADER + b"\x01" + body
    return Ether(src=own, dst=DTP_MAC, type=len(payload)) / Raw(payload)

def on_packet(pkt):
    if not pkt.haslayer(Dot3) or pkt[Dot3].src == own:
        return
    if parse_dtp(bytes(pkt[Dot3].payload)) is not None:
        sendp(advertisement(), iface="sw0", verbose=False)

sendp(advertisement(), iface="sw0", verbose=False)
sniffer = AsyncSniffer(iface="sw0", store=False, prn=on_packet)
sniffer.start()
threading.Event().wait(float(os.environ["RUN_SECONDS"]))
try:
    sniffer.stop()
except Exception:
    pass
'

AUDIT_CODE='
import os, threading
from macabre.attacks.dtp_audit import DtpAuditConfig, run_dtp_audit
stop = threading.Event()
threading.Timer(float(os.environ["LISTEN_SECONDS"]), stop.set).start()
stats = run_dtp_audit(DtpAuditConfig(iface="att0", probe=True), stop, lambda _s: None)
print(f"Audit: frames heard {stats.frames_seen}, probe sent {stats.probe_sent}, trunk answer {stats.trunk_answer}")
for neighbor in stats.neighbors.values():
    print(f"Audit: port {neighbor.mac} advertised status 0x{neighbor.status:02x}, encapsulation 0x{neighbor.encapsulation:02x}, domain {neighbor.domain}")
print(f"Audit: {stats.status}")
'

run_phase() {
    local mode="$1"
    echo "Phase: simulated port in $mode mode"
    ip netns exec switch env PYTHONPATH="$ROOT/src" MODE="$mode" RUN_SECONDS="$((LISTEN_SECONDS + 3))" \
        "$PY" -c "$PORT_CODE" 2>"$WORK/port_$mode.err" &
    local port_pid=$!
    sleep 2
    ip netns exec attacker env PYTHONPATH="$ROOT/src" LISTEN_SECONDS="$LISTEN_SECONDS" \
        "$PY" -c "$AUDIT_CODE" > "$WORK/audit_$mode.txt" 2>"$WORK/audit_$mode.err" || true
    wait "$port_pid" || true
    cat "$WORK/audit_$mode.txt"
    echo
}

WORK="$(mktemp -d)"
chmod 755 "$WORK"
cleanup() {
    stop_lab
    rm -rf "$WORK"
}
trap cleanup EXIT

run_phase trunk
run_phase access

TRUNK_OK=0
ACCESS_OK=0
grep -q "negotiates trunks" "$WORK/audit_trunk.txt" && TRUNK_OK=1
grep -q "does not negotiate a trunk here" "$WORK/audit_access.txt" && ACCESS_OK=1
if [[ "$TRUNK_OK" -eq 1 && "$ACCESS_OK" -eq 1 ]]; then
    echo "Result: the audit read the trunk and access statuses from the simulated ports, and its verdict followed each mode. The status mapping is not checked against a real switch."
else
    echo "Result: the verdicts did not match the simulated modes. Result unreliable. See $WORK for the phase output."
    exit 1
fi
