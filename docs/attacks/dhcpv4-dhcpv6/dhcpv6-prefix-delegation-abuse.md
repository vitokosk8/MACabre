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

## Related

The other techniques in this family are listed in the [family index](README.md).
