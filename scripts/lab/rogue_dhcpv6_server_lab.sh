#!/usr/bin/env bash
# Isolated rogue DHCPv6 server lab (Linux only, needs root). NOT YET VALIDATED.
#
# Planned topology, all inside network namespaces on one bridge (the LAN):
#
#   server:   dnsmasq as the legitimate DHCPv6 server (2001:db8::1/64), giving DNS
#             server 2001:db8::53.
#   attacker: MACabre's rogue DHCPv6 server, answering with DNS server 2001:db8:bad::53.
#   client:   a DHCPv6 client that sends SOLICIT and REQUEST and prints the DNS server
#             it received.
#
#   Phase 1 (baseline): the legitimate server runs. The client gets 2001:db8::53.
#   Phase 2 (attack):   the legitimate server is stopped. The client gets 2001:db8:bad::53.
#
# This script only checks that the kernel has IPv6 and then reports inconclusive, because
# the sandbox kernel used for development has no IPv6 in network namespaces. The phases
# above are not implemented yet; they need a Linux machine with IPv6 enabled.
#
# Nothing here touches the host's real network interfaces.
#
# Usage:
#   sudo scripts/lab/rogue_dhcpv6_server_lab.sh

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
