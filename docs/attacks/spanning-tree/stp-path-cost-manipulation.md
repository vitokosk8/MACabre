# STP Path Cost Manipulation

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P2

## What it abuses

Each port's path cost determines which link the spanning tree prefers. Advertising a lower cost makes a link look shorter, and the tree moves traffic onto it, even if that link is slower or less reliable.

## Protocols involved

- IEEE 802.1D (path cost)
- IEEE 802.1t path cost values

## Goal

Attract traffic to a chosen link by advertising a lower path cost.

## How it works

The attacker advertises a root path cost that is lower than the real one. Switches that trust the advertisement choose a different root port, which moves traffic to a different path. The traffic is still forwarded, but on a link that was not planned for it.

## What an auditor checks

- Compare the chosen root ports with the intended design.
- Check path costs on every trunk.
- Test whether cost changes are logged.

## Defenses

- Explicit path costs on critical links.
- Root Guard and BPDU Guard on edge ports.
- Monitoring of topology changes.

## Implementation status

Implemented in MACabre as its own panel entry, "STP Path Cost Manipulation". It uses the root bridge impersonation sender and sets the advertised root path cost, so it shares code with [Root Bridge Impersonation](root-bridge-impersonation.md). Real switches are not tested.

## Lab validation

Lab: `scripts/lab/root_bridge_impersonation_lab.sh`. Advertising a cost of 0 moves the switch's root port to the attacker's port (phase 2). Advertising a cost of 1000, above the real path cost, leaves the root port on the real root (phase 4). Exit 0 when both hold.

## Related

The other techniques in this family are listed in the [family index](README.md).
