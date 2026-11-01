# MLD Spoofing / Flooding

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

Multicast Listener Discovery (MLD) lets IPv6 routers learn which hosts want which multicast groups. Snooping switches use MLD reports to forward multicast only where it is needed, so forged or excessive reports change where multicast goes.

## Protocols involved

- Multicast Listener Discovery v1 and v2 (RFC 2710, RFC 3810)
- IPv6 multicast

## Goal

Receive multicast groups the attacker should not get, or disturb their forwarding.

## How it works

The attacker sends MLD reports for groups it does not need. A snooping switch adds the attacker's port to the group, and multicast for that group is delivered to it. A stream of reports also loads the switch and the snooping table.

## What an auditor checks

- Test whether a report from an access port changes forwarding.
- Measure the report rate the switch handles.
- Check whether MLD snooping and querier election are configured.

## Defenses

- MLD snooping with a fixed querier.
- Rate limits for MLD on access ports.
- Monitoring of group membership changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
