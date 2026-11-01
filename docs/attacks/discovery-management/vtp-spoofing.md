# VTP Spoofing

**Family**: Discovery & Management Protocols · **Priority**: P2

## What it abuses

VLAN Trunking Protocol (VTP) lets switches share their VLAN database. Advertisements are accepted from any trunk, and a switch that accepts a higher-revision advertisement replaces its own VLAN database with the one it received.

## Protocols involved

- VLAN Trunking Protocol (VTP, Cisco)
- IEEE 802.1Q

## Goal

Replace the VLAN database of every switch in the domain.

## How it works

The attacker sends VTP advertisements with a higher configuration revision and a chosen VLAN list. The switches accept it and delete or add VLANs across the domain. Hosts lose their VLANs, or traffic moves into VLANs the attacker chose.

## What an auditor checks

- List the VTP domain, mode and revision on each switch.
- Test whether a VTP advertisement from a trunk is accepted.
- Check whether a VTP password is set.

## Defenses

- VTP transparent or off mode where VLANs are configured statically.
- VTP version 3 with a password.
- Monitoring of VTP revision changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
