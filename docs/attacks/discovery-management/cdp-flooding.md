# CDP Flooding

**Family**: Discovery & Management Protocols · **Priority**: P1

## What it abuses

A switch stores a neighbor entry for each CDP device it hears. Sending CDP advertisements with many different identities fills that table and uses processing on the switch.

## Protocols involved

- Cisco Discovery Protocol (CDP)

## Goal

Fill the neighbor table of a switch with false devices.

## How it works

The attacker sends CDP advertisements with random device identities at a high rate. The switch creates an entry for each one, and its neighbor table and processing grow. Legitimate neighbor entries may be evicted.

## What an auditor checks

- Count the neighbor entries created under a CDP stream.
- Check the table size and the eviction behavior.
- Check whether the switch rate-limits CDP.

## Defenses

- Disable CDP on access ports.
- Rate limits for control protocols on access ports.
- Monitoring of neighbor table size.

## Related

The other techniques in this family are listed in the [family index](README.md).
