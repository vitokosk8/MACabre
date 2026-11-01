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

## Related

The other techniques in this family are listed in the [family index](README.md).
