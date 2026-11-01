# IGMP Leave Spoofing

**Family**: L2 Multicast & Broadcast · **Priority**: P2

## What it abuses

A host that leaves a group sends an IGMP leave, and a snooping switch removes its port from the group once the leave is confirmed. A forged leave makes the switch remove a port that still has a receiver, so the receiver stops getting the stream.

## Protocols involved

- IGMP version 2 leave (RFC 2236)
- IGMP snooping

## Goal

Remove receivers from a group, by sending leaves on their behalf.

## How it works

The attacker sends a leave for a group with the source address of a receiver on another port. The switch removes that receiver's port, and the receiver stops receiving the stream until it sends a new report. Repeating the leave keeps the receiver out of the group.

## What an auditor checks

- Test whether a leave from another port removes a receiver.
- Check how quickly the receiver rejoins.
- Check whether the leave is logged.

## Defenses

- Snooping that checks the port and the source of a leave.
- Fast-leave disabled where it is not needed.
- Monitoring of membership changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
