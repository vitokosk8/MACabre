# ARP spoofing

**Family**: ARP · **Priority**: P1

## What it abuses

ARP has no authentication. A host keeps a cache that maps IP addresses to MAC addresses, and it updates that cache from replies it did not ask for. A forged reply is accepted as long as it arrives on the segment.

## Protocols involved

- **ARP** (RFC 826): resolves an IPv4 address to a MAC address on Ethernet. A reply says "this IP is at this MAC".

## Goal

Make a victim send the traffic meant for one IP address (usually the gateway) to the attacker's MAC. That gives the attacker a man-in-the-middle position for the victim's traffic.

## How it works

1. The attacker sends an ARP reply to the victim: the gateway's IP is at the attacker's MAC.
2. The victim updates its cache entry for the gateway.
3. The victim sends gateway traffic to the attacker, until the entry expires or the real gateway answers again.

## What an auditor checks

- The victim's ARP cache for the gateway, before and after the attack.
- Whether the victim accepts unsolicited replies, and for how long the entry stays poisoned.
- Whether the switch or the host detects the change of MAC for the IP.

## Defenses

- **Dynamic ARP Inspection** with DHCP snooping, which drops replies that do not match the binding table.
- **Static ARP entries** for gateways and critical servers.
- **Detection of IP-to-MAC changes**, for example with `arpwatch`.

## Related

[ARP cache poisoning](arp-cache-poisoning.md) applies the same idea to both ends of a conversation.
