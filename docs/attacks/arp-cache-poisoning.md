# ARP cache poisoning

**Family**: ARP · **Priority**: P1

## What it abuses

The same flaw as ARP spoofing: ARP replies are not authenticated. Poisoning becomes a full man-in-the-middle when both directions of a conversation are poisoned, and when the poisoning is kept alive.

## Protocols involved

- **ARP** (RFC 826) over Ethernet.

## Goal

Place the attacker between two hosts, usually a victim and its gateway, so that traffic in both directions passes through the attacker.

## How it works

1. Send a forged reply to the victim: the gateway's IP is at the attacker's MAC.
2. Send a forged reply to the gateway: the victim's IP is at the attacker's MAC.
3. Repeat both replies periodically, so the entries never expire.

Both caches now point to the attacker. Forwarding the traffic onward keeps the connection working, and the victim never notices.

## What an auditor checks

- Both caches, before and after the attack.
- Whether the poisoning holds over time, with periodic replies.
- Whether the hosts or the switch detect the conflict.
- Whether the sensitive traffic is encrypted, which limits what an interceptor can read.

## Defenses

- **Dynamic ARP Inspection** and **static ARP entries** on the victim and the gateway.
- **Encryption end to end** (TLS, SSH, IPsec), so an intercepted connection still protects its data.
- **802.1X** on access ports, so an attacker needs an authenticated port first.

## Related

[ARP spoofing](arp-spoofing.md) poisons one entry. This technique poisons both sides and keeps them poisoned.
