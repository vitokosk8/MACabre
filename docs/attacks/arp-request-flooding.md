# ARP request flooding

**Family**: ARP · **Priority**: P1

## What it abuses

Every broadcast on a segment has to be processed by every host, and a router or host that owns the requested IP answers every sender. ARP tables and rate limits are finite, but the protocol does not limit how many requests a sender may make.

## Protocols involved

- **ARP** (RFC 826): the who-has request is broadcast to the segment.

## Goal

Consume resources: CPU on the hosts and the router, and space in the neighbor tables. When the router's table is full, new hosts cannot be resolved, and existing entries may be evicted.

## How it works

1. Generate requests with random sender MAC and IP addresses from a subnet.
2. Choose the target: a fixed IP, such as the gateway, or random hosts of the subnet.
3. Send them as fast as the interface allows.

A host that owns the target answers every sender, so its table grows with each distinct address. That is the mechanism to measure, because it shows the limit of the table.

## What an auditor checks

- How many requests per second the router and the hosts can process before they degrade.
- How many entries the target's neighbor table holds after the flood, and how fast entries are evicted.
- Whether ARP rate limiting or control-plane policing reacts.

## Defenses

- **ARP rate limiting** on switch ports and **control-plane policing** on the router.
- **Bounded neighbor tables** with eviction policies, sized for the network.
- **Dynamic ARP Inspection**, which drops ARP packets whose sender IP and MAC do not match the DHCP snooping binding table.

## Related

[ARP spoofing](arp-spoofing.md) and its variants change what hosts believe. This technique only changes how much work they do.
