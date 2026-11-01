# SLAAC Prefix Spoofing

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

Stateless Address Autoconfiguration lets hosts build their own IPv6 addresses from a prefix in an RA. A forged prefix makes hosts configure addresses in a range the operator did not assign, which can redirect traffic or cause conflicts with real addresses.

## Protocols involved

- IPv6 SLAAC (RFC 4862)
- ICMPv6 Router Advertisement, Prefix Information option (RFC 4861)

## Goal

Make hosts configure addresses in a prefix chosen by the attacker, to redirect or conflict their traffic.

## How it works

The attacker sends an RA with a prefix it chooses. Hosts generate addresses from that prefix and use the new prefix to route. Depending on the prefix, traffic leaves through the attacker or the hosts conflict with addresses that already exist.

## What an auditor checks

- Test whether a forged prefix is accepted.
- List the addresses each host generates from it.
- Check the lifetimes and the preferred values of the prefix.

## Defenses

- RA Guard on access ports.
- Monitoring of prefixes on each segment.
- DHCPv6 for address assignment where SLAAC is not needed.

## Related

The other techniques in this family are listed in the [family index](README.md).
