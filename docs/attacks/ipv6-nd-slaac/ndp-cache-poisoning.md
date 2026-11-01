# NDP Cache Poisoning

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

The neighbor cache is the IPv6 counterpart of the ARP cache. Any Neighbor Discovery message that updates it can be used to poison it, and combining NA and NS forgery makes the attack reliable.

## Protocols involved

- ICMPv6 Neighbor Discovery (RFC 4861)
- Neighbor cache behavior of hosts and routers

## Goal

Redirect IPv6 traffic for chosen addresses to the attacker, by corrupting neighbor caches.

## How it works

The attacker uses NA and NS messages to set and refresh false bindings. Hosts and routers keep the entries until they expire or are replaced. Traffic for the target address then goes to the attacker, and the audit measures how long the poisoning holds.

## What an auditor checks

- Measure how long a poisoned entry persists.
- Compare the cache behavior of hosts and routers.
- Check whether unsolicited updates are accepted.

## Defenses

- Neighbor Discovery inspection.
- SEND where possible.
- Shorter reachable times on sensitive segments.

## Related

The other techniques in this family are listed in the [family index](README.md).
