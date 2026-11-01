# Rogue DHCP Server

**Family**: DHCPv4 & DHCPv6 · **Priority**: P1

## What it abuses

A DHCP client accepts the first valid OFFER it receives, and the protocol has no server authentication. A device that answers DHCP requests with its own addresses, gateway and DNS servers can become the configuration source for the segment.

## Protocols involved

- DHCPv4 (RFC 2131, RFC 2132 options)

## Goal

Become the configuration source of clients, so that their gateway and DNS traffic passes through the attacker.

## How it works

The rogue server listens for DISCOVER messages and answers with an OFFER that carries its own gateway and DNS server. Clients that get there first configure themselves with those values, and their traffic goes through the rogue server, which is a man-in-the-middle position.

## What an auditor checks

- Detect any DHCP server other than the authorized ones.
- Check which server answers first from each access port.
- Check that clients refuse offers from unexpected servers.

## Defenses

- DHCP snooping with trusted ports only at the real servers.
- Monitoring for unexpected DHCP servers.
- Dynamic ARP Inspection, so that a rogue server cannot change the bindings silently.

## Related

The other techniques in this family are listed in the [family index](README.md).
