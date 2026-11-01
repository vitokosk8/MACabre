# Root Bridge Takeover

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P1

## What it abuses

The root bridge is the reference point of the spanning tree. Whoever is root decides which paths forward traffic. A device that advertises a better bridge ID, usually a lower priority, becomes root and attracts traffic to the paths it chooses.

## Protocols involved

- IEEE 802.1D (bridge priority and bridge ID)
- IEEE 802.1w, 802.1s

## Goal

Become the root bridge, so that the attacker's bridge is the center of the forwarding paths.

## How it works

The attacker advertises a bridge ID lower than the current root's. The election moves to it, and the spanning tree is rebuilt around it. The paths that carry traffic change, and any traffic that was unintended for that path may now cross links it should not.

## What an auditor checks

- Compare the root bridge with the intended design.
- Check the priority of every bridge and whether it can be lowered from an access port.
- Test whether a root change is detected and reported.

## Defenses

- Root Guard on access ports and on ports toward distribution switches.
- Fixed priorities on core switches.
- Alerts on root changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
