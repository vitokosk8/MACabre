# Root Bridge Impersonation

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P1

## What it abuses

A device can impersonate the root bridge by copying its bridge ID, so that other switches consider it the same root. This is harder to notice than a takeover, because the root identity looks unchanged in the output of most tools.

## Protocols involved

- IEEE 802.1D bridge identifier

## Goal

Appear as the root bridge without being it, to receive or disturb traffic that follows the tree.

## How it works

The attacker copies the root's bridge ID and sends BPDUs with it. The switches see a root that appears to be unchanged, but the advertisements come from a different port. Depending on the implementation, traffic may flow through the impostor on some segments.

## What an auditor checks

- Check for duplicate bridge IDs.
- Check whether the switch reports a second device with the root identity.
- Check which port the root BPDUs arrive on.

## Defenses

- Root Guard.
- Monitoring of root port changes and of advertisements from unexpected ports.
- BPDU Guard on access ports.

## Implementation status

Implemented in MACabre as a sender with the root's copied ID. The panel sets the real root's priority and MAC, and the advertised root path cost. The cost option covers the path-cost variant of this attack, so no separate STP Path Cost Manipulation module is needed. Real switches are not tested.

## Lab validation

Lab: `scripts/lab/root_bridge_impersonation_lab.sh` (Linux bridge with kernel STP, three namespaces). Phase 2 advertises cost 0 and the switch's root port moves to the attacker's port for the whole run. Phase 4 advertises cost 1000, above the real path cost, and the root port stays on the real root. Exit 0 when both results hold. This shows that the advertised cost decides the port. Real Cisco or other vendor switches are not tested.

## Related

The other techniques in this family are listed in the [family index](README.md).
