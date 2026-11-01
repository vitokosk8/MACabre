# IGMP Spoofing

**Family**: L2 Multicast & Broadcast · **Priority**: P2

## What it abuses

IGMP lets hosts join multicast groups by sending membership reports. Snooping switches use those reports to decide where to forward a group. The reports are not authenticated, so a host can join any group and receive its traffic.

## Protocols involved

- IGMP version 2 (RFC 2236) and version 3 (RFC 3376)
- IGMP snooping

## Goal

Receive multicast groups the attacker should not get, by joining them.

## How it works

The attacker sends IGMP membership reports for the groups it wants. The snooping switch adds the attacker's port to the group, and the multicast stream for that group is delivered there. The attacker receives traffic that is meant for other hosts.

## What an auditor checks

- Test whether a report from an access port adds it to a group.
- Check whether the switch limits groups per port.
- Check whether the joins are logged.

## Defenses

- Limits on groups per port.
- Filtering of multicast on access ports.
- Monitoring of group membership.

## Related

The other techniques in this family are listed in the [family index](README.md).
