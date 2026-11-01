# Native VLAN Abuse

**Family**: VLAN & IEEE 802.1Q · **Priority**: P1

## What it abuses

Frames on the native VLAN of a trunk are sent untagged. If the two ends of a trunk disagree about the native VLAN, or the native VLAN carries user traffic, frames can end up in a different VLAN than intended.

## Protocols involved

- IEEE 802.1Q
- Trunk native VLAN configuration

## Goal

Move frames between VLANs by exploiting a native VLAN mismatch or user traffic in the native VLAN.

## How it works

A mismatch between native VLANs makes untagged frames from one side appear on the other side in a different VLAN. The attacker uses that difference to send traffic into a VLAN it should not reach, or to receive traffic that is supposed to stay in the native VLAN.

## What an auditor checks

- Compare the native VLAN on both ends of every trunk.
- List the hosts that send untagged traffic on trunks.
- Check whether the native VLAN is also used for management or user access.

## Defenses

- Identical native VLAN on both ends.
- Native VLAN dedicated to an unused VLAN.
- Tagging of native VLAN traffic.

## Related

The other techniques in this family are listed in the [family index](README.md).
