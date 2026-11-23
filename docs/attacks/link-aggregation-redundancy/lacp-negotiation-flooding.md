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

## Implementation

- Module: `src/macabre/attacks/lacp_negotiation_flooding.py`, panel `LACP Negotiation Flooding`.
- LACPDUs go to the Slow Protocols address with the claimed actor fields and an empty partner, as in LACP Spoofing.
- The actor state cycles through the configured values (default `0x3F` and `0x07`), one LACPDU every `interval` seconds (default 0.02 s, at least 0.01 s, 200 frames by default).
- The run reports the number of state changes sent. Dry run builds the plan and sends nothing.

## Lab validation

`scripts/lab/lacp_negotiation_flooding_lab.sh` runs the bonding driver in 802.3ad mode with one attacker port and no real partner. It records the partner churn count and the partner port state the member reports in `/proc/net/bonding/bond0`, in a control phase and during a 15 s flood of 750 LACPDUs. Exit 0 means the bond accepted the claimed partner and either its churn grew by at least two or its partner port state changed at least two times. First VM run: the bond accepted the partner and churn stayed at 0, so the port state was then sampled. Two VM runs with the sampled port state: exit 0, with 55 and 48 partner port state changes during the flood. Scope: a Linux bonding lab, not traffic disruption and not vendor aggregates. Status 🧪 Tested.

## Related

The other techniques in this family are listed in the [family index](README.md).
