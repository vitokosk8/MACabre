# NDP Neighbor Cache Exhaustion

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

A router keeps a neighbor cache entry for each address it tries to reach, including addresses that do not answer. A large subnet, such as a /64, offers an enormous address space, so scanning it fills the cache with incomplete entries.

## Protocols involved

- ICMPv6 Neighbor Discovery (RFC 4861)
- IPv6 subnet addressing

## Goal

Fill the router's neighbor cache with incomplete entries, so that real hosts cannot be resolved.

## How it works

The attacker sends packets to many addresses on the subnet, or sends NS messages for them, so the router creates incomplete neighbor entries. The cache reaches its limit, and the router drops or delays resolution for real hosts, which is the IPv6 version of ARP table exhaustion.

## What an auditor checks

- Measure the router's neighbor cache size and its limit.
- Test how fast incomplete entries are created.
- Check whether real hosts still resolve during the flood.

## Defenses

- Neighbor cache limits and timeouts on routers.
- Rate limits for neighbor resolution.
- Monitoring of incomplete entries.

## Related

The other techniques in this family are listed in the [family index](README.md).
