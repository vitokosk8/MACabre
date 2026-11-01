# EVPN MAC/IP Advertisement Poisoning

**Family**: Carrier Ethernet & Data Center · **Priority**: P3

## What it abuses

EVPN uses BGP to advertise which MAC and IP addresses are behind which provider edge. A route that claims a MAC and IP address on another edge redirects traffic for that host. The BGP session must be protected, or the route can be forged.

## Protocols involved

- EVPN (RFC 7432)
- BGP (RFC 4271)

## Goal

Redirect traffic for a host, by advertising its addresses from another edge.

## How it works

The attacker sends or influences an EVPN MAC/IP advertisement that claims a host's addresses on another edge. Other edges install the route, and traffic for the host is sent to the attacker's edge. The effect is the same as ARP poisoning, at the level of the fabric.

## What an auditor checks

- Check the BGP session protection and the peers.
- Test whether a route from an unexpected peer is accepted.
- Check the EVPN routes against the expected host locations.

## Defenses

- Authenticated BGP sessions and strict peer lists.
- Route filters on the advertised MAC and IP.
- Monitoring of EVPN route changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
