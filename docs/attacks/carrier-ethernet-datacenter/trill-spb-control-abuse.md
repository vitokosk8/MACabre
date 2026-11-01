# TRILL / SPB Control Abuse

**Family**: Carrier Ethernet & Data Center · **Priority**: P3

## What it abuses

TRILL (RFC 6325) and Shortest Path Bridging (IEEE 802.1aq) use link-state routing between bridges to compute forwarding paths. Their routing messages are not authenticated in all deployments, so a forged link-state message can change paths and install a false view of the topology.

## Protocols involved

- TRILL (RFC 6325, IS-IS based)
- IEEE 802.1aq (SPB)
- IS-IS

## Goal

Change the forwarding paths by injecting false link-state information.

## How it works

The attacker sends link-state messages that describe a link or bridge that does not exist, or that claim a shorter path through the attacker. The bridges recompute their forwarding, and traffic follows the path the attacker chose.

## What an auditor checks

- Check the authentication of link-state messages.
- Test whether a message from an access port is accepted.
- Check the link-state database for unknown bridges.

## Defenses

- Authenticated routing messages.
- Restriction of routing messages to core ports.
- Monitoring of link-state changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
