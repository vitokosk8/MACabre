# Gratuitous ARP spoofing

**Family**: ARP · **Priority**: P1

## What it abuses

A gratuitous ARP is a legitimate announcement: a host that gets an IP address, or that moves to a new MAC, tells the segment about it. Every host that caches that IP is expected to update its entry. Nothing checks who is allowed to make the announcement.

## Protocols involved

- **ARP** (RFC 826): the gratuitous form is an ARP request whose sender and target IP are the same address, sent to broadcast.
- **RFC 5227**: IPv4 address conflict detection, which relies on these announcements.

## Goal

Redirect traffic for an IP address across the whole segment with a single broadcast. Unlike ARP spoofing, no victim is chosen: every host that caches the IP is affected at once.

## How it works

1. The attacker broadcasts an announcement: the gateway's IP is at the attacker's MAC.
2. Each host that caches the gateway's IP updates its entry.
3. Traffic for the gateway goes to the attacker, on every host that accepted the announcement.

## What an auditor checks

- The ARP caches of several hosts, before and after one announcement.
- Whether the hosts accept an announcement for an address they already hold.
- Whether the switch or the hosts detect a duplicate address for the gateway's IP.

## Defenses

- **Dynamic ARP Inspection**, which drops announcements that do not match the binding table.
- **Static ARP entries** for the gateway on critical hosts.
- **Duplicate address detection** and alerts on a gateway MAC change.
- **Legitimate redundancy protocols** (VRRP, HSRP) handle gateway failover without relying on announcements from random hosts.

## Related

[ARP spoofing](arp-spoofing.md) targets one host with a reply. A gratuitous announcement targets everyone who caches the IP.
