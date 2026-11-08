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

## Implementation status

Implemented in MACabre as its own panel entry. The module sends one Router Advertisement per made-up router: each has a distinct link-local source (fe80::1 onwards), a distinct /64 from the prefix base, a router lifetime, and hop limit 255. All frames come from the operator's MAC.

## Lab validation

Lab: `scripts/lab/router_advertisement_flooding_lab.sh` (Linux, IPv6 kernel, one bridge, namespaces). Control: the victim has no default router and no address in the prefix base. Attack: 20 RAs, each with a different router and /64 inside 2001:db8:f100::/48. Exit 0 when the victim accepts at least two of the routers and at least one address from the flood. Validated on Ubuntu (VM) at commit 10fdf08, exit 0: the victim accepted 20 of 20 routers and configured 15 SLAAC addresses from the flood. Processing cost and the full table limits of each OS are not measured.

## Related

The other techniques in this family are listed in the [family index](README.md).
