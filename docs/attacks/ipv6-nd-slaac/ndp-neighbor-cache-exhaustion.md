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

## Implementation status

Implemented in MACabre as its own panel entry. The module sends Neighbor Solicitations to a target on the segment, each from a new source address inside a /64 you choose, with the operator's MAC as the source link-layer option, from the operator's MAC, hop limit 255. Not yet validated on a host.

## Lab validation

Lab: `scripts/lab/ndp_neighbor_cache_exhaustion_lab.sh` (Linux, IPv6 kernel, one bridge, namespaces). Control: the victim's cache holds no entry for the spoofed sources. Attack: 200 solicitations, each from a new source in 2001:db8:c0::/64. Exit 0 when the victim creates at least 150 entries for those sources. The lab prints the victim's total entries and the kernel's gc_thresh3 limit; it does not reach that limit, so the table-exhaustion effect itself is not measured. Not validated yet: the lab is pending a run on Ubuntu (VM).

## Related

The other techniques in this family are listed in the [family index](README.md).
