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

## Implementation status

Implemented in MACabre as its own panel entry, "STP Priority Manipulation". It targets the designated port of a shared segment, not the root: the attacker advertises the real root's ID, the switch's root path cost, and a lower bridge priority. It is not the same as Root Bridge Takeover, which changes the root. Real switches are not tested.

## Lab validation

Lab: `scripts/lab/stp_priority_manipulation_lab.sh`. On a segment shared with the attacker, the switch's port sw-x forwards with no attacker, and it stays forwarding when the attacker advertises a worse priority (control). With priority 0 it is blocking for the whole run (attack), and it forwards again after the attacker stops. The switch's root port stays on the real root. Exit 0 when all hold.

## Related

The other techniques in this family are listed in the [family index](README.md).
