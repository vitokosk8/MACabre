# Rogue Router Advertisement

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P1

## What it abuses

Hosts learn their default router from Router Advertisements (RA), and RAs are not authenticated by default. A device that sends an RA with a router lifetime makes itself the default router for every host that accepts it.

## Protocols involved

- ICMPv6 Router Advertisement (RFC 4861)
- IPv6 Stateless Address Autoconfiguration (RFC 4862)

## Goal

Become the default router of the segment, and receive the hosts' off-link traffic.

## How it works

The attacker sends RAs advertising itself as a router with a non-zero lifetime. Hosts add it to their default router list and send off-link traffic through it. The attacker can then intercept and forward traffic for the whole segment.

## What an auditor checks

- Test whether RAs from a non-router port are accepted.
- Check the default router list on each host after the RA.
- Check whether RA Guard is active on access ports.

## Defenses

- RA Guard on access switch ports (RFC 6105).
- Monitoring of RAs from unknown sources.
- Static default routes on critical hosts.

## Related

The other techniques in this family are listed in the [family index](README.md).
