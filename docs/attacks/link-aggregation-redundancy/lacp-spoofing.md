# LACP Spoofing

**Family**: Link Aggregation & Redundancy · **Priority**: P2

## What it abuses

Link Aggregation Control Protocol (LACP) bundles several physical links into one logical link, and both ends exchange LACPDUs to agree on the bundle. LACPDUs are not authenticated, so a device can send them and take part in the negotiation.

## Protocols involved

- IEEE 802.1AX (Link Aggregation, LACP)

## Goal

Create or change an aggregate, so that traffic is delivered to the attacker's port.

## How it works

The attacker sends LACPDUs that advertise a partner with a chosen system and key. The switch forms or changes a bundle with the attacker's port. Traffic that the switch hashes onto that bundle can then be delivered to the attacker, or the real bundle can be broken.

## What an auditor checks

- Test whether LACPDUs from an access port form a bundle.
- Check which ports a bundle includes after the test.
- Check whether a bundle change is logged.

## Defenses

- LACP only on ports that are configured for it.
- Disable LACP on access ports.
- Monitoring of aggregate membership.

## Implementation status

Implemented in MACabre as a sender with an actor system ID, key and port number of the operator's choice, and an empty partner. The panel generates a random system ID when the field is empty. Validated on the Linux bonding lab; real switches are not tested.

## Lab validation

Lab: `scripts/lab/lacp_spoofing_lab.sh` (Linux bonding driver in 802.3ad mode, in namespaces). Control phase: with no LACPDUs, the bond reports no partner (00:00:00:00:00:00). Attack phase: the bond reports the claimed system ID as its partner. The lab needs the `bonding` kernel module and exits 2 without it. Validated on Ubuntu (VM) at commit 089ec70: control partner 00:00:00:00:00:00, attack partner 02:00:00:00:00:c1, exit 0. Vendor aggregates are not tested.

## Related

The other techniques in this family are listed in the [family index](README.md).
