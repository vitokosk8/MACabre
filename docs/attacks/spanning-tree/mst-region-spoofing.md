# MST Region Spoofing

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P3

## What it abuses

MSTP groups VLANs into instances and divides the network into regions. Switches in the same region must agree on the region name, revision and VLAN-to-instance mapping. A device that advertises a different region, or the same region with different mappings, can split the tree or move VLANs onto other paths.

## Protocols involved

- IEEE 802.1s (MSTP)
- MST configuration digest

## Goal

Move VLANs onto other spanning-tree paths by faking a region or its mapping.

## How it works

The attacker sends BPDUs that carry a region identity and a mapping. If a switch trusts them, the region boundary moves, and some VLANs are placed in instances that forward on different paths. Traffic for those VLANs changes route, and the tree may be split.

## What an auditor checks

- Compare the region name, revision and mapping on every switch.
- Test whether a foreign region is detected and reported.
- Check which instance each VLAN uses.

## Defenses

- Identical region configuration on all switches.
- BPDU Guard on edge ports.
- Monitoring of region digest mismatches.

## Related

The other techniques in this family are listed in the [family index](README.md).
