# LACP Negotiation Flooding

**Family**: Link Aggregation & Redundancy · **Priority**: P2

## What it abuses

LACP keeps state for each aggregate and each member, and it processes each LACPDU it receives. A stream of LACPDUs forces repeated state changes and uses control-plane capacity.

## Protocols involved

- IEEE 802.1AX (LACP)

## Goal

Make the members change state repeatedly, disturbing traffic on the aggregate.

## How it works

The attacker sends LACPDUs at a high rate, with changing state values. The switch updates the state of the members each time. Members may flap between states, which disturbs traffic on the aggregate even if the attack does not change its membership.

## What an auditor checks

- Measure the switch's LACP processing rate.
- Check whether the members flap under the stream.
- Check whether LACP rate limits are configured.

## Defenses

- Rate limits for LACPDUs on untrusted ports.
- Control-plane policing.
- Monitoring of member state changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
