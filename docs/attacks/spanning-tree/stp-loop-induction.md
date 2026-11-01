# STP Loop Induction

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P2

## What it abuses

Spanning Tree prevents loops by blocking ports. If blocking is disrupted, for example by making the tree believe a link is not redundant, two active paths form a loop, and broadcast and multicast frames circulate without end.

## Protocols involved

- IEEE 802.1D
- IEEE 802.1w, 802.1s

## Goal

Create a loop, so that broadcast and multicast frames circulate and saturate the network.

## How it works

The attacker advertises a topology in which a redundant link appears to be a non-loop path, or stops sending BPDUs on it. The switches unblock the port, and traffic loops. Broadcast storms and MAC table instability follow.

## What an auditor checks

- Check whether a blocked port can be unblocked by BPDUs from an access port.
- Test loop detection and the time it takes to react.
- Check whether storm control is enabled.

## Defenses

- BPDU Guard and Root Guard.
- Storm control and loop protection on access ports.
- Monitoring of blocked and forwarding port counts.

## Related

The other techniques in this family are listed in the [family index](README.md).
