# BPDU Flooding

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P1

## What it abuses

Switches process every BPDU they receive, and their control plane has finite capacity. A stream of BPDUs, even well-formed ones, can consume that capacity and delay the processing of real spanning-tree messages.

## Protocols involved

- IEEE 802.1D
- IEEE 802.1w, 802.1s

## Goal

Overload the switch's control plane, so that real spanning-tree messages are delayed.

## How it works

The attacker sends a high rate of BPDUs on an access port. The switch parses and compares each one, and its control plane work grows. Real spanning-tree updates may be delayed, which can lengthen convergence after a real failure.

## What an auditor checks

- Measure the switch's BPDU processing rate under load.
- Check whether BPDUs are rate-limited per port.
- Check whether convergence time grows during the flood.

## Defenses

- BPDU Guard on access ports, which shuts the port on the first BPDU.
- Control-plane policing for BPDUs.
- Rate limits on untrusted ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
