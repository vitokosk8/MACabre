# IGMP Snooping Table Exhaustion

**Family**: L2 Multicast & Broadcast · **Priority**: P3

## What it abuses

A snooping switch keeps a table of groups and ports. The table has a fixed size, and a large number of joins for distinct groups fills it. When the table is full, the switch cannot learn new groups, and traffic for them is flooded.

## Protocols involved

- IGMP snooping (RFC 4541)
- IGMP version 3 (RFC 3376)

## Goal

Fill the snooping table, so that new groups are flooded.

## How it works

The attacker sends reports for many distinct groups. The switch creates an entry for each one until the table is full. New groups, including legitimate ones, are then flooded to every port, which is the multicast version of MAC table overflow.

## What an auditor checks

- Compare the table size with the number of groups in use.
- Test how many groups from one port fill the table.
- Check the behavior of new groups when the table is full.

## Defenses

- Limits on groups per port.
- Table sizes adequate for the groups in use.
- Monitoring of table utilization.

## Related

The other techniques in this family are listed in the [family index](README.md).
