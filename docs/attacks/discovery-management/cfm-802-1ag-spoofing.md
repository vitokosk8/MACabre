# CFM / 802.1ag Spoofing

**Family**: Discovery & Management Protocols · **Priority**: P3

## What it abuses

Connectivity Fault Management (CFM, IEEE 802.1ag) detects faults in a bridged network with maintenance points that send continuity messages. A forged continuity message from a maintenance point with another identifier can hide a fault or create a false alarm.

## Protocols involved

- IEEE 802.1ag (CFM)
- ITU-T Y.1731 (OAM functions for Ethernet)

## Goal

Hide a fault, or raise a false alarm, by impersonating a maintenance point.

## How it works

The attacker sends continuity check messages that carry a maintenance point identifier the network expects. The monitoring points record the link as healthy, even if it is not, or they record a fault when none exists. The audit checks whether faults are believed on the basis of identifiers alone.

## What an auditor checks

- List the maintenance points and their identifiers.
- Test whether a foreign identifier is accepted.
- Check whether the monitoring system compares identifiers.

## Defenses

- Maintenance point identifiers reviewed against an inventory.
- Monitoring of CFM alarms.
- Access control on the segments where CFM runs.

## Related

The other techniques in this family are listed in the [family index](README.md).
