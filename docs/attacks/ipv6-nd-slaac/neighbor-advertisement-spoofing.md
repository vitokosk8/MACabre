# Neighbor Advertisement Spoofing

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P1

## What it abuses

Neighbor Discovery replaces ARP for IPv6. Neighbor Advertisements (NA) tell hosts which link-layer address owns an IPv6 address, and hosts update their neighbor cache from them without verifying the sender.

## Protocols involved

- ICMPv6 Neighbor Discovery (RFC 4861)
- IPv6 over Ethernet

## Goal

Receive traffic meant for an IPv6 address, by claiming that address in neighbor advertisements.

## How it works

The attacker sends unsolicited NA messages that claim a victim's IPv6 address, with the attacker's MAC in the target link-layer option. Neighbors that accept the advertisement send traffic for the victim to the attacker, which is the IPv6 counterpart of ARP spoofing.

## What an auditor checks

- Test whether unsolicited NA messages update the neighbor cache.
- Check which hosts accept the binding.
- Check whether ND inspection or SEND is deployed.

## Defenses

- Neighbor Discovery inspection on access switches.
- SEND (RFC 3971) where hosts support it.
- Monitoring of neighbor cache changes on routers.

## Related

The other techniques in this family are listed in the [family index](README.md).
