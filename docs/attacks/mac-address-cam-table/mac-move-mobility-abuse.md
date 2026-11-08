# MAC Move / Mobility Abuse

**Family**: MAC Address & CAM Table · **Priority**: P2

## What it abuses

Some networks allow a host to move between ports, for example after a VM migration, and the switch updates its table when that happens. The same mobility logic can be triggered on purpose by a host that is not moving, so the table follows a false location.

## Protocols involved

- IEEE 802.1D MAC learning
- Vendor MAC mobility features and move detection

## Goal

Redirect traffic for a target MAC address to the attacker's port by making the network believe the host moved.

## How it works

A host sends frames as if it had moved to another port, usually with a MAC address that belongs to a legitimate host. The switch updates the entry, and frames for that address follow the new location. Legitimate moves and forged moves look the same on the wire, so the difference has to come from policy, such as the number of moves per minute or the set of ports allowed for that address.

## What an auditor checks

- Test whether a move is logged, and whether the switch limits how many moves it accepts.
- Check that moves between ports outside an allowed set are rejected.
- Measure how long traffic takes to return to the real host.

## Defenses

- Move detection with thresholds and alerts.
- Port restrictions for addresses that should never move.
- Use of 802.1X or static entries for sensitive hosts.

## Implementation status

The module sends one or a few frames that carry the target MAC as source, from the attacker's port. Frames are sent once: a move, not a continuous flap. The GUI panel exposes the host MAC and the number of frames.

## Lab validation

`scripts/lab/mac_move_lab.sh` builds a Linux bridge with a victim, an attacker and a monitor port. The victim's entry is dynamic, learned from its own traffic. Phase 0 delivers the monitor's unicast traffic to the victim. Phase 1 sends one move frame from the attacker's port. Phase 2 shows the entry on the attacker's port and all unicast traffic for the victim's MAC arriving at the attacker.

The lab shows that a single frame moves a dynamic entry on this bridge. It does not test move limits, move logging, or allowed-port policies, which the Linux bridge does not have. Those need a real switch.

## Related

The other techniques in this family are listed in the [family index](README.md).
