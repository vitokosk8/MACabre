# DHCP Spoofing

**Family**: DHCPv4 & DHCPv6 · **Priority**: P1

## What it abuses

DHCP messages are not authenticated, so a device can forge OFFER, ACK or other server replies. The forged message only has to arrive before the real one, which makes the outcome a race rather than a protocol decision.

## Protocols involved

- DHCPv4 (RFC 2131)
- IEEE 802.3 broadcast

## Goal

Win the race against the real server, and give clients the attacker's configuration.

## How it works

The attacker answers each DISCOVER or REQUEST with a forged reply that carries the attacker's values. If it is faster than the real server, the client accepts it. Forging replies needs no access to the server, only to the segment.

## What an auditor checks

- Measure how often a forged reply arrives before the real one.
- Check which values the client keeps after the reply.
- Check whether the client logs the server it accepted.

## Defenses

- DHCP snooping that only trusts ports where the real servers are.
- Consistent DHCP server placement.
- Monitoring of DHCP lease records against the client MACs.

## Related

The other techniques in this family are listed in the [family index](README.md).
