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

## Implementation status

- Module: `src/macabre/attacks/qinq_stacking_abuse.py` (one-shot send of frames with an 802.1ad outer tag, TPID 0x88A8, around an 802.1Q inner tag).
- GUI panel: "QinQ / VLAN Stacking Abuse".
- Status: 🔨 Implemented. Not yet validated by the lab on this kernel.

## Lab validation

`scripts/lab/qinq_stacking_lab.sh` builds a VLAN-filtering bridge with an 802.1ad outer tag as the provider edge. Phase 0 drops the stacked frame when the customer port is not a member of the service VLAN; phase 1 forwards it with outer and inner tags intact. The lab needs bridge VLAN filtering in the kernel. On the sandbox kernel that option is unavailable, so the lab reports inconclusive (exit 2) and the attack is not yet validated here. It must be run on a kernel with bridge VLAN filtering, or on a real provider edge.
