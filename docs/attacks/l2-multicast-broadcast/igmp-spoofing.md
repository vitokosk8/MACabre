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

## Implementation status

- Module: `src/macabre/attacks/igmp_spoofing.py` (sends IGMPv2 membership reports for the groups given, one per group and count, from the operator's MAC and address).
- GUI panel: "IGMP Spoofing".
- Status: 🔨 Implemented. The lab validates that the bridge's snooping table learns the group on the attacker's port after one report. Delivery of the group's traffic is not validated: this sandbox kernel does not deliver a registered group to a port with flooding of unknown multicast turned off, so delivery needs the target switch.

## Lab validation

`scripts/lab/igmp_spoofing_lab.sh` runs a snooping bridge with an attacker port and a sender port. Before the report the bridge has no entry for the group on the attacker's port. After one IGMPv2 report from that port it has one. The lab does not measure group limits, querier behavior, report suppression or logging on a real switch.

## Related

The other techniques in this family are listed in the [family index](README.md).
