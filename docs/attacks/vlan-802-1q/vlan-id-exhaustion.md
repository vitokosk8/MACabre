# VLAN ID Exhaustion

**Family**: VLAN & IEEE 802.1Q · **Priority**: P3

## What it abuses

Switches have finite resources for VLANs: VLAN IDs, VLAN database entries and per-VLAN state, such as spanning-tree instances. Creating many VLANs, or many VLAN instances, can exhaust those resources and disrupt the switch.

## Protocols involved

- IEEE 802.1Q
- Vendor VLAN and spanning-tree instance limits

## Goal

Use up the VLAN and instance resources of a switch, so that new VLANs fail or the control plane slows down.

## How it works

The attacker sends frames or advertisements that cause the switch to create many VLANs or VLAN instances. Each one takes memory and control-plane work. When the limit is reached, new VLANs fail, and the switch may slow down or drop control traffic.

## What an auditor checks

- Compare the number of VLANs in use with the platform limit.
- Check what the switch logs when a limit is reached.
- Check whether VLAN creation can be triggered from access ports.

## Defenses

- Dynamic VLAN creation disabled.
- Monitoring of VLAN count against the platform limit.
- Static VLAN configuration with an explicit list.

## Related

The other techniques in this family are listed in the [family index](README.md).
