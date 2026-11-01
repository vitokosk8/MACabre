# LACP Partner Impersonation

**Family**: Link Aggregation & Redundancy · **Priority**: P2

## What it abuses

A link aggregate has a partner: the device at the other end, identified by its system ID and key. A device that presents the same system ID and key can take the partner's place in the negotiation, and the switch treats the new device as the legitimate partner.

## Protocols involved

- IEEE 802.1AX (LACP, system ID and key)

## Goal

Take the place of an aggregate's partner, so that the switch moves the bundle to the attacker.

## How it works

The attacker copies the partner's system identifier and key and sends LACPDUs from another port. The switch sees the same partner identity and may move the aggregate to the new port, or accept the attacker's bundle as the partner. The traffic follows the new path.

## What an auditor checks

- Compare the partner system IDs with the expected devices.
- Test whether a copied identity is accepted on another port.
- Check whether the switch alerts when a partner moves.

## Defenses

- Fixed partner identities on critical aggregates.
- Port security on aggregate members.
- Monitoring of partner changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
