#!/usr/bin/env bash
# Isolated DHCPv6 starvation lab (Linux only, needs root). NOT YET VALIDATED.
#
# Planned topology, all inside network namespaces on one bridge (the LAN):
#
#   server:   dnsmasq as a DHCPv6 server with a small IA_NA pool (2001:db8::100-10f).
#   attacker: MACabre's DHCPv6 starvation with random client identities.
#   client:   a legitimate DHCPv6 client, which requests one address.
#
#   Phase 1 (baseline): the client gets an address from the pool.
#   Phase 2 (attack):   the attacker runs until the pool is used up. The client's request
#                       then gets no address.
#
# This script only checks that the kernel has IPv6 and then reports inconclusive, because
# the sandbox kernel used for development has no IPv6 in network namespaces. The phases
# above are not implemented yet; they need a Linux machine with IPv6 enabled.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/dhcpv6_starvation_lab.sh

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This lab needs root: run it with sudo." >&2
    exit 1
fi

if [[ ! -d /proc/sys/net/ipv6 ]]; then
    echo "Result: inconclusive. This kernel has no IPv6 support, so DHCPv6 cannot be tested in network namespaces here. Run the lab on a Linux machine with IPv6 enabled; its phases are described above and are not implemented yet."
    exit 2
fi

echo "Result: inconclusive. IPv6 is available, but the lab phases are not implemented yet. See the topology comments above."
exit 2
