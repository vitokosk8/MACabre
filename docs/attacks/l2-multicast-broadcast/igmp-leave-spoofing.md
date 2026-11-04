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

## Implementation status

- Module: `src/macabre/attacks/igmp_leave_spoofing.py` (sends IGMPv2 leave messages for the groups given, to 224.0.0.2, one per group and count, from the operator's MAC and address).
- GUI panel: "IGMP Leave Spoofing".
- Status: 🔨 Implemented. The lab validates that a leave from a host that never joined removes the group from a shared switch port. Vendor leave handling is not validated.

## Lab validation

`scripts/lab/igmp_leave_spoofing_lab.sh` runs a snooping bridge, with a segment bridge behind one port holding a victim and an attacker. The victim joins the group, and the membership stays for six seconds with no leave. After one leave from the attacker, the membership is removed from the shared port within about two seconds. The lab does not measure group-specific queries, timer values or other vendors' behavior.

## Related

The other techniques in this family are listed in the [family index](README.md).
