# SLAAC Configuration Abuse

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P1

## What it abuses

An RA carries more than a prefix: it can set the DNS server, the MTU, the hop limit and the routes. Hosts apply these options when they are valid, so a forged RA can change how a host resolves names and reaches other networks.

## Protocols involved

- IPv6 SLAAC (RFC 4862)
- Recursive DNS Server option in RA (RFC 8106)
- ICMPv6 Router Advertisement options (RFC 4861)

## Goal

Change the DNS server, the MTU or the routes that hosts receive from router advertisements.

## How it works

The attacker sends an RA that includes a Recursive DNS Server option pointing to its own server, or changes the MTU or routes. Hosts apply the values, so name resolution or path selection goes through the attacker, without any change on the host.

## What an auditor checks

- Test whether a forged DNS option is applied.
- Check the MTU and route options on each host.
- Verify that the hosts log the source of the options.

## Defenses

- RA Guard on access ports.
- Encrypted DNS and verified time sources where possible.
- Monitoring of DNS configuration on clients.

## Related

The other techniques in this family are listed in the [family index](README.md).
