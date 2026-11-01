# Neighbor Solicitation Spoofing

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P1

## What it abuses

Neighbor Solicitations (NS) ask which link-layer address owns an IPv6 address. The NS carries the sender's link-layer address, and receivers may record it, so a forged NS can plant a binding without any reply being needed.

## Protocols involved

- ICMPv6 Neighbor Discovery (RFC 4861)
- Duplicate Address Detection

## Goal

Plant a false neighbor binding without waiting for any reply.

## How it works

The attacker sends NS messages that carry a chosen source link-layer address for a victim's IPv6 address. Hosts that record the source option store the attacker's MAC, and later traffic follows that entry. The attacker does not need to answer anything.

## What an auditor checks

- Test whether NS source link-layer options create entries.
- Check how hosts treat NS for addresses they own.
- Verify that entries learned from NS are marked as such.

## Defenses

- Neighbor Discovery inspection.
- SEND where supported.
- Monitoring of cache entries learned from NS.

## Related

The other techniques in this family are listed in the [family index](README.md).
