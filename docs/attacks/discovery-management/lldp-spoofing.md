# LLDP Spoofing

**Family**: Discovery & Management Protocols · **Priority**: P1

## What it abuses

The Link Layer Discovery Protocol (LLDP) is the open standard for announcing a device's identity and port. Its announcements are not authenticated, so a host can present a false chassis ID or port ID, and tools that rely on LLDP draw the wrong topology.

## Protocols involved

- IEEE 802.1AB (LLDP)

## Goal

Insert false neighbor information into topology tools, to hide a problem or cause a wrong change.

## How it works

The attacker sends LLDP frames that claim a chassis and a port name chosen by the attacker. The switch and the network management tools record it as a neighbor. Because topology maps and cable checks use LLDP, the false entry can hide a real problem or cause a wrong change.

## What an auditor checks

- Test whether an LLDP frame from an access port creates a neighbor entry.
- Check which tools use LLDP data and how they display it.
- Verify that the switch logs the source of each neighbor.

## Defenses

- Disable LLDP on ports where it is not needed.
- Management tools that compare LLDP data with an inventory.
- Monitoring of neighbor changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
