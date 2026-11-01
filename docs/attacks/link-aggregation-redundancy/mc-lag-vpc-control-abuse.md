# MC-LAG / vPC Control Abuse

**Family**: Link Aggregation & Redundancy · **Priority**: P3

## What it abuses

Multi-chassis link aggregation (MC-LAG, vPC) lets two switches present one logical aggregate to a host. The switches coordinate through a peer link and a keepalive. Forged keepalive or peer messages can make both switches believe they are the only active peer.

## Protocols involved

- Vendor MC-LAG and vPC control plane
- IEEE 802.1AX

## Goal

Cause split brain, so that both switches act as the active peer.

## How it works

The attacker sends control messages that claim a failed peer or a different role. Both switches may become active at once, which is called split brain. Hosts then send traffic to both, and some of it is dropped or duplicated.

## What an auditor checks

- Check the keepalive path and whether it is separate from data traffic.
- Test whether a control message from an access port is accepted.
- Check the split-brain behavior in a lab.

## Defenses

- Dedicated keepalive links, not shared with data.
- Authentication of control messages where supported.
- Monitoring of peer state.

## Related

The other techniques in this family are listed in the [family index](README.md).
