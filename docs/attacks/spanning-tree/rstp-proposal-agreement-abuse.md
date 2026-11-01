# RSTP Proposal/Agreement Abuse

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P3

## What it abuses

RSTP speeds up convergence with a proposal and agreement handshake, which lets a port move to forwarding without waiting for timers. Forged proposals or agreements can make a port forward before the tree is ready.

## Protocols involved

- IEEE 802.1w (RSTP proposal and agreement)

## Goal

Force a port to forward before the topology is agreed, to create a path or a temporary loop.

## How it works

The attacker sends proposal BPDUs with the flags that trigger a rapid transition. A port that accepts them moves to forwarding before the tree has agreed on the topology, which can create a temporary loop or an unexpected path.

## What an auditor checks

- Test whether proposals from an access port trigger a transition.
- Measure the time between proposal and forwarding.
- Check whether the switch logs unexpected agreements.

## Defenses

- Edge ports configured as edge, with BPDU Guard.
- Monitoring of rapid transitions.
- Consistent RSTP configuration across all switches.

## Related

The other techniques in this family are listed in the [family index](README.md).
