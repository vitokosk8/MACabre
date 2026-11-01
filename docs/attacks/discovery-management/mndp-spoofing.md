# MNDP Spoofing

**Family**: Discovery & Management Protocols · **Priority**: P1

## What it abuses

MikroTik Neighbor Discovery Protocol (MNDP) is MikroTik's own neighbor announcement, sent over UDP port 5678 and broadcast on each interface where it is enabled. RouterOS shows the results in its neighbor list, with the identity, platform, board, version and address of each neighbor. The announcements are not authenticated, so a host can announce itself as a MikroTik router with any identity and address it likes.

## Protocols involved

- MikroTik Neighbor Discovery Protocol (MNDP, UDP port 5678, broadcast)

## Goal

Make an attacker appear as a trusted MikroTik router in the neighbor list, so that an operator who uses the list to find devices connects to the attacker, or so that the list gives a false inventory.

## How it works

The attacker sends MNDP announcements that name a chosen identity, board and address. Each RouterOS device that receives the announcement adds the attacker to its neighbor list, and a tool that reads that list reports the false device.

## What an auditor checks

- Test whether an MNDP announcement from an access port creates a neighbor entry on RouterOS.
- Check whether MNDP is enabled on ports where it is not needed.
- Check whether the neighbor list is used for any decision, such as choosing a device to manage.

## Defenses

- Disable MNDP on access ports and untrusted interfaces, or on all interfaces that do not need it.
- Do not use the neighbor list as a source of truth for inventory or management.
- Restrict management access with an address list and a management VLAN, not by neighbor name.

## Related

The other techniques in this family are listed in the [family index](README.md).
