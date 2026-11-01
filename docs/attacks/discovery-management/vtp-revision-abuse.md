# VTP Revision Abuse

**Family**: Discovery & Management Protocols · **Priority**: P2

## What it abuses

VTP keeps the revision number of the VLAN database, and a switch accepts any advertisement with a higher number. The number is a counter that any sender can set high, so the revision alone does not show whether a change is legitimate.

## Protocols involved

- VLAN Trunking Protocol (VTP, Cisco)

## Goal

Make the switches accept a database, by giving it a higher revision number.

## How it works

The attacker sends an advertisement with a revision far above the current one. Every switch that receives it replaces its database, even if the VLANs in the message are wrong. Because the revision is never reset in practice, the attacker's database stays in place.

## What an auditor checks

- Compare the revision number of each switch with the intended value.
- Test whether a large revision jump is accepted.
- Check whether the switches alert on revision changes.

## Defenses

- VTP transparent mode on switches that do not share VLANs.
- Password protection.
- Monitoring of revision changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
