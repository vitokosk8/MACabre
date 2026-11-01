# EVPN MAC Mobility Abuse

**Family**: Carrier Ethernet & Data Center · **Priority**: P3

## What it abuses

EVPN tracks a host that moves between edges with a MAC mobility sequence number. The edge with the higher number wins. A route with a forged, higher sequence number makes other edges move the host to the attacker's location.

## Protocols involved

- EVPN MAC mobility extended community (RFC 7432)
- BGP (RFC 4271)

## Goal

Move a host's MAC address to the attacker's location, with a higher sequence number.

## How it works

The attacker advertises a MAC route with a sequence number higher than the current one. The edges accept it and move the MAC to the attacker's edge. The change looks like a legitimate move, so detection depends on checks on the move rate and the origin.

## What an auditor checks

- Check the sequence numbers of current routes.
- Test whether a higher sequence number from an unexpected edge is accepted.
- Check whether moves are limited and logged.

## Defenses

- Limits on MAC moves per time window.
- Authenticated BGP sessions.
- Monitoring of mobility events.

## Related

The other techniques in this family are listed in the [family index](README.md).
