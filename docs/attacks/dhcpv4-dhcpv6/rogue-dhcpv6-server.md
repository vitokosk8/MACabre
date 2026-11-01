# Rogue DHCPv6 Server

**Family**: DHCPv4 & DHCPv6 · **Priority**: P1

## What it abuses

DHCPv6 has the same trust problem as DHCPv4: clients accept advertisements from any server that replies. A rogue DHCPv6 server can give clients addresses, DNS servers and domain names, and it can answer before the real server.

## Protocols involved

- DHCPv6 (RFC 8415)
- IPv6 multicast to All_DHCP_Relay_Agents_and_Servers

## Goal

Become the configuration source of IPv6 clients, including their DNS servers.

## How it works

The rogue server listens for SOLICIT messages sent to the DHCPv6 multicast group, and answers with an ADVERTISE that carries its values. Clients that accept the advertisement use the rogue server's DNS and address, which gives the attacker a position on the path.

## What an auditor checks

- Detect DHCPv6 servers other than the authorized ones.
- Check which advertisement the client selects.
- Check whether clients can be configured to use a preferred server.

## Defenses

- DHCPv6 snooping on access ports.
- RA Guard and DHCPv6 guard on the switch.
- Monitoring for unexpected DHCPv6 servers.

## Related

The other techniques in this family are listed in the [family index](README.md).
