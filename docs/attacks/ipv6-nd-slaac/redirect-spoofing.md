# Redirect Spoofing

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

A router sends an ICMPv6 Redirect to tell a host that a better next hop exists for a destination. Hosts accept redirects that come from their current router, so a forged redirect that looks as if it came from the router can change the path of one destination.

## Protocols involved

- ICMPv6 Redirect (RFC 4861)
- IPv6 neighbor cache

## Goal

Change the path of traffic for one destination, by sending a forged redirect.

## How it works

The attacker sends a Redirect to a host, claiming that the router is not the best next hop for a destination and that a specific host is. The host adds a route entry and sends that destination's traffic through the attacker. Because the change is per destination, it is hard to see from the router.

## What an auditor checks

- Test whether redirects from a non-router source are accepted.
- Check the route cache after a redirect.
- Check whether redirects are disabled on hosts that do not need them.

## Defenses

- Ignoring redirects on hosts that do not need them.
- Redirect filtering on access switches.
- Monitoring of route changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
