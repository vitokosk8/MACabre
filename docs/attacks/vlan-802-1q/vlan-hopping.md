# VLAN Hopping

**Family**: VLAN & IEEE 802.1Q · **Priority**: P1

## What it abuses

VLAN hopping means reaching a VLAN that the attacker's port is not a member of. The two classic routes are switch spoofing, which makes the port a trunk, and double tagging, which uses the native VLAN. Both defeat the logical separation that VLANs are supposed to provide.

## Protocols involved

- IEEE 802.1Q
- DTP (Cisco)
- Native VLAN handling on trunks

## Goal

Reach a VLAN that the attacker's port does not belong to.

## How it works

Using switch spoofing, the port becomes a trunk and carries all VLANs. Using double tagging, a frame with two tags is sent through a trunk whose native VLAN matches the attacker's VLAN, and the outer tag is removed by the first switch, so the inner tag takes it to a different VLAN. Each route depends on a specific misconfiguration, so the audit checks for each one.

## What an auditor checks

- Check for dynamic trunk ports.
- Check that the native VLAN is not used for user traffic.
- Check that access ports drop tagged frames.

## Defenses

- Access mode on all user ports, with DTP off.
- A dedicated, unused native VLAN.
- Tag all native-VLAN frames on trunks (vlan dot1q tag native).

## Related

The other techniques in this family are listed in the [family index](README.md).
