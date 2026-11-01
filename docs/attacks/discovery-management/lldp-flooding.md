# LLDP Flooding

**Family**: Discovery & Management Protocols · **Priority**: P1

## What it abuses

A device that receives LLDP frames stores one neighbor entry for each distinct chassis and port it hears. A stream with many distinct identities fills that table and loads the device.

## Protocols involved

- IEEE 802.1AB (LLDP)

## Goal

Fill the neighbor table with false devices, and disturb the real topology data.

## How it works

The attacker sends LLDP frames with random chassis and port identities. The device creates an entry for each, and its neighbor table and processing grow. Real neighbors may be dropped from the table, which affects topology information.

## What an auditor checks

- Count the neighbor entries created under an LLDP stream.
- Check the table size and the timeout of entries.
- Check whether real neighbors survive the stream.

## Defenses

- Disable LLDP on untrusted ports.
- Rate limits for LLDP on access ports.
- Monitoring of neighbor table size.

## Related

The other techniques in this family are listed in the [family index](README.md).
