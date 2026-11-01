# VLAN Translation Abuse

**Family**: VLAN & IEEE 802.1Q · **Priority**: P3

## What it abuses

Some switches translate one VLAN ID into another at the edge of a network, for example between an access VLAN and a provider VLAN. A translation rule that maps two VLANs onto the same ID, or maps unexpected IDs, merges traffic that should be separate.

## Protocols involved

- IEEE 802.1Q
- Vendor VLAN translation (mapping) features

## Goal

Reach a VLAN that a translation rule maps onto a VLAN the attacker should not reach.

## How it works

A host sends frames in a VLAN that the translation maps to a VLAN it should not reach. Because translation is done silently, the traffic passes without any tag rewriting the host can see. The audit reviews the mapping and tests the edge cases.

## What an auditor checks

- Export the translation table and look for collisions.
- Test traffic from each source VLAN and record the target VLAN.
- Check that unused VLAN IDs are not mapped.

## Defenses

- Review translation tables as part of configuration audits.
- Map only VLAN IDs that are needed.
- Document translation rules next to the VLAN design.

## Related

The other techniques in this family are listed in the [family index](README.md).
