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

## Implementation status

Implemented in MACabre as its own panel entry. The module sends Router Advertisements with router lifetime 0, so the sender is not offered as a default router, and one autonomous Prefix Information option for a fraudulent /64, with valid and preferred lifetimes. Source link-local is derived from the operator's MAC, hop limit 255. Not yet validated on a host.

## Lab validation

Lab: `scripts/lab/slaac_prefix_spoofing_lab.sh` (Linux, IPv6 kernel, one bridge, namespaces). Setup: a legitimate router advertises 2001:db8:5000::/64, and the victim must take its default route and an address there. Control: the victim has no address in the fraudulent 2001:db8:bad:1::/64. Attack: three RAs with router lifetime 0 for the fraudulent prefix. Exit 0 when the victim configures an address in the fraudulent prefix and keeps the legitimate router as its default. Not validated yet: the lab is pending a run on Ubuntu (VM).

## Related

The other techniques in this family are listed in the [family index](README.md).
