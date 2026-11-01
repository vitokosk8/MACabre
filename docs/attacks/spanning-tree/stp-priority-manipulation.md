# STP Priority Manipulation

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P2

## What it abuses

The bridge priority decides the root election. A device that advertises a lower priority than the current root takes the role, which is the simplest way to change the topology.

## Protocols involved

- IEEE 802.1D (bridge priority)
- IEEE 802.1w, 802.1s

## Goal

Become the root by advertising a lower bridge priority.

## How it works

The attacker advertises a bridge priority lower than the current root's. Because the priority is the first part of the bridge ID, it wins the election, and the tree is rebuilt around the attacker.

## What an auditor checks

- List the bridge priorities and the intended root.
- Test whether a low priority from an access port is accepted.
- Check that root changes are reported.

## Defenses

- Fixed low priorities on core switches.
- Root Guard on access ports.
- BPDU Guard on edge ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
