# Double-Tagging

**Family**: VLAN & IEEE 802.1Q · **Priority**: P1

## What it abuses

A frame with two 802.1Q tags is handled by the first switch as if it belonged to the native VLAN, and the outer tag is removed. The second switch then forwards the inner tag to its VLAN. This moves traffic across VLANs in one direction, without any trunk negotiation.

## Protocols involved

- IEEE 802.1Q tagging
- Native VLAN behavior on trunks

## Goal

Send frames across a VLAN boundary in one direction, using the native VLAN of a trunk.

## How it works

The attacker sends a frame carrying an outer tag for the native VLAN and an inner tag for the target VLAN. The first switch removes the outer tag at the trunk, because the frame looks native there. The second switch then sees only the inner tag and forwards the frame into the target VLAN. The traffic is one way, because the reply cannot carry the same structure.

## What an auditor checks

- Test whether frames with two tags are dropped at the access port.
- Check whether the native VLAN of trunks matches a user VLAN.
- Check that the switch tags native-VLAN traffic.

## Defenses

- Native VLAN unused for user traffic.
- Tagging of native VLAN traffic on trunks.
- Dropping of frames with unexpected tag stacks on access ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
