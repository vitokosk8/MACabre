# Router Advertisement Flooding

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

Hosts keep a limited list of default routers and a limited list of prefixes learned from RAs. A stream of RAs with many different routers or prefixes fills those lists, and each RA costs processing on every host.

## Protocols involved

- ICMPv6 Router Advertisement (RFC 4861)
- IPv6 SLAAC (RFC 4862)

## Goal

Fill the hosts' router and prefix lists, and load their processing.

## How it works

The attacker sends many RAs, each with a different router address or prefix. Hosts store them until their lists are full, which can evict the real default router or create many addresses from fake prefixes. Processing grows with the rate, which affects the hosts as well.

## What an auditor checks

- Count how many RAs per second a host processes before it degrades.
- Check whether the legitimate default router survives the flood.
- Check the list limits on each operating system.

## Defenses

- RA Guard on access ports.
- Rate limits for RA on access ports.
- Monitoring of RA counts on each VLAN.

## Related

The other techniques in this family are listed in the [family index](README.md).
