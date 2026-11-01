# QinQ / VLAN Stacking Abuse

**Family**: VLAN & IEEE 802.1Q · **Priority**: P2

## What it abuses

QinQ (IEEE 802.1ad) puts a provider tag outside the customer tag. A provider edge that trusts the customer's tags can be pushed to forward frames with a chosen provider tag, or to strip tags it should keep.

## Protocols involved

- IEEE 802.1ad (provider bridges)
- IEEE 802.1Q

## Goal

Choose the provider service that a customer frame uses, by controlling the outer tag.

## How it works

The customer sends frames that already carry a provider tag, or several tags, and the edge forwards them according to the tags it sees. If the edge does not overwrite the outer tag, the customer chooses which provider service the frame uses.

## What an auditor checks

- Test frames with extra tags on the customer port.
- Check that the provider edge sets the outer tag itself.
- Check how the provider edge handles stacked tags it does not expect.

## Defenses

- Provider edge that rewrites the outer tag on ingress.
- Drop frames with unexpected tags at the customer port.
- Customer and provider tag ranges kept separate.

## Related

The other techniques in this family are listed in the [family index](README.md).
