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

## Implementation status

Implemented in MACabre as its own panel entry. The module sends unsolicited Neighbor Advertisements for a target address you choose, with the Override flag set and the Target Link-Layer Address option carrying the operator's MAC, from the operator's MAC, hop limit 255. Validated on Linux IPv6 with a victim host that accepts unsolicited NAs by default. Real routers and RA Guard are not tested.

## Lab validation

Lab: `scripts/lab/ndp_cache_poisoning_lab.sh` (Linux, IPv6 kernel, one bridge, namespaces). Setup: the victim pings the peer, so its neighbor cache holds the peer's MAC. Control: the entry still holds the peer's MAC. Attack: three unsolicited NAs with the Override flag binding the peer's address to the attacker's MAC. Exit 0 when the entry changes to the attacker's MAC. Validated on Ubuntu (VM) at commit 8bc5391, exit 0: the victim's neighbor cache for the peer changed from the peer's MAC to the attacker's MAC after three unsolicited NAs with the Override flag.

## Related

The other techniques in this family are listed in the [family index](README.md).
