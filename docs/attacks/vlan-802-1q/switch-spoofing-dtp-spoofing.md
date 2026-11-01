# Switch Spoofing / DTP Spoofing

**Family**: VLAN & IEEE 802.1Q · **Priority**: P1

## What it abuses

Switches negotiate trunks with DTP (Cisco) on ports that allow it. A device that sends DTP frames can be negotiated into a trunk, and then it receives tagged traffic for all VLANs the trunk carries.

## Protocols involved

- Dynamic Trunking Protocol (DTP, Cisco)
- IEEE 802.1Q trunking

## Goal

Turn an access port into a trunk, so that the attacker receives traffic for every VLAN.

## How it works

A host sends DTP messages that advertise trunk capability. A port that is set to dynamic mode accepts the negotiation and becomes a trunk. The host then sees tagged frames for every allowed VLAN, which breaks the separation the access port was meant to give.

## What an auditor checks

- List the ports in dynamic or desirable mode.
- Check that access ports are fixed to access mode.
- Confirm that a trunk negotiation on an access port is logged.

## Defenses

- Set access ports to static access mode, with DTP disabled.
- Use the nonegotiate option on trunks that should not negotiate.
- Shut down unused ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
