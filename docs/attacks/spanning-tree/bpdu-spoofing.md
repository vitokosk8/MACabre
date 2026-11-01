# BPDU Spoofing

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P1

## What it abuses

Spanning Tree relies on bridge protocol data units (BPDUs) to elect a root bridge and choose forwarding ports. BPDUs are not authenticated, so a host that sends them can take part in the topology calculation as if it were a switch.

## Protocols involved

- IEEE 802.1D (STP)
- IEEE 802.1w (RSTP)
- IEEE 802.1Q MSTP

## Goal

Insert false spanning-tree information to change the topology.

## How it works

The attacker sends configuration BPDUs that advertise a better root bridge than the current one. The switches accept the advertisement, recalculate the tree, and change the forwarding ports, which can move traffic or create a loop.

## What an auditor checks

- Check whether BPDUs are accepted on access ports.
- Measure how long the topology takes to converge after an injected BPDU.
- Check whether the switch logs root changes.

## Defenses

- BPDU Guard on access ports.
- Root Guard on ports where the root must not move.
- Explicit root priority on the intended root bridge.

## Related

The other techniques in this family are listed in the [family index](README.md).
