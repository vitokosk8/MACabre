# DHCPv6 Prefix Delegation Abuse

**Family**: DHCPv4 & DHCPv6 · **Priority**: P3

## What it abuses

DHCPv6 prefix delegation gives a requesting router a block of addresses to use downstream. A device that requests many prefixes, or that is not a router, can take a large share of the delegation pool, and it can also install itself as a router for the delegated networks.

## Protocols involved

- DHCPv6 prefix delegation (RFC 8415, RFC 3633 lineage)
- IPv6 routing

## Goal

Obtain a block of prefixes, and install the attacker as a router for them.

## How it works

The attacker requests prefixes from the delegating server and receives a block. It then announces itself as a router for those prefixes. Other hosts that learn the new prefix may route through it, and the delegation pool shrinks for legitimate routers.

## What an auditor checks

- List the authorized delegating routers and the clients that request prefixes.
- Test whether a non-router can request a prefix.
- Check the pool size and the limit per client.

## Defenses

- Prefix delegation only on trusted ports and to authorized clients.
- Per-client limits on delegated prefixes.
- RA Guard on access ports.

## Implementation status

Implemented in MACabre as its own panel entry. The module sends DHCPv6 SOLICIT messages with an IA_PD option and a prefix length hint (/48 to /64), with random DUID-LL identities. For each ADVERTISE that offers a prefix, it sends a REQUEST for that prefix, and counts the REPLY messages that confirm it. The count of confirmed prefixes is the measure of how much of the delegation pool it holds. Installing the attacker as a router for those prefixes is not implemented: it needs Router Advertisements, which the RA techniques in this suite cover.

## Lab validation

Lab: `scripts/lab/dhcpv6_prefix_delegation_abuse_lab.sh` (Linux, IPv6 kernel, Kea DHCPv6 server, one bridge, namespaces). Kea delegates /56 prefixes from 2001:db8:f000::/48, a pool of 256. Control: a legitimate requesting router gets a prefix before the attack. Attack: the attacker requests 300 prefixes with random identities; the lab expects at least 255 confirmed (the control holds one). Test: the legitimate router, with a new identity, must get no prefix. Exit 0 when all hold. Result on an OrbStack Ubuntu VM with Kea 2.6.3: PASS (verdict "Vulnerable"). Control: the legitimate router got 2001:db8:f000::/56 before the attack. Attack: 300 SOLICIT, 255 REQUEST and 255 prefixes confirmed by the server, out of a pool of 256. Test: the legitimate router, with a new identity, got no prefix. Scope: the lab gives the server a neighbour entry for each legitimate client and for each attacker identity (a seeded sequence of 300), so the server can answer them. On a real link that depends on neighbour discovery and is not measured here.

## Related

The other techniques in this family are listed in the [family index](README.md).
