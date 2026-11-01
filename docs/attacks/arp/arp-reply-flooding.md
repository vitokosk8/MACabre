# ARP Reply Flooding

**Family**: ARP · **Priority**: P1

## What it abuses

Hosts and routers accept ARP replies, and each reply costs processing and changes cache state. A stream of replies, even harmless ones, can consume CPU on the receiving hosts and churn their caches.

## Protocols involved

- ARP (RFC 826)
- IEEE 802.3 broadcast or unicast delivery

## Goal

Load the victims' CPUs and disturb their ARP caches with a stream of replies.

## How it works

The attacker sends a large number of replies to hosts on the segment. Each host must parse and validate every reply, and may update its cache for each entry. Sustained streams keep the CPU busy and make the cache unstable, which can disturb normal traffic.

## What an auditor checks

- Count the replies each host processes per second before performance drops.
- Check whether the router or the switch rate-limits ARP.
- Observe cache churn during the flood.

## Defenses

- ARP rate limiting on switch ports.
- Control-plane policing on routers.
- Dynamic ARP Inspection, which drops replies that do not match trusted bindings.

## Related

The other techniques in this family are listed in the [family index](README.md).
