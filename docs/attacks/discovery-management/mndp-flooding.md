# MNDP Flooding

**Family**: Discovery & Management Protocols · **Priority**: P1

## What it abuses

MNDP announcements are sent as broadcast UDP datagrams and are processed by every RouterOS device that receives them. Each announcement creates or refreshes a neighbor entry, so a stream of announcements costs the receiving device processing time and memory.

## Protocols involved

- MikroTik Neighbor Discovery Protocol (MNDP, UDP port 5678, broadcast)

## Goal

Fill the neighbor list of RouterOS devices with invented neighbors, and make them process a steady stream of announcements.

## How it works

The attacker sends MNDP announcements with a different invented identity and address each time. Each receiving device adds an entry, and the list grows until it is cleared or the entries expire.

## What an auditor checks

- Measure the number of neighbor entries created at a set rate.
- Check whether the list is capped or aged, and how long entries remain.
- Check whether the device's CPU and log use change while the flood runs.

## Defenses

- Disable MNDP on access ports and untrusted interfaces.
- Limit the rate of broadcast UDP on the switch, if the switch can.
- Keep management traffic on a separate VLAN, so the neighbor list is smaller.

## Related

The other techniques in this family are listed in the [family index](README.md).
