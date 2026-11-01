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

## Related

The other techniques in this family are listed in the [family index](README.md).
