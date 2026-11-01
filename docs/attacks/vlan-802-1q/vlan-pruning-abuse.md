# VLAN Pruning Abuse

**Family**: VLAN & IEEE 802.1Q · **Priority**: P2

## What it abuses

VTP pruning removes VLANs from trunks that have no members on the other side, to reduce flooding. A forged or manipulated VLAN advertisement can make a switch prune VLANs that are still in use, which breaks connectivity on that VLAN.

## Protocols involved

- VLAN Trunking Protocol (VTP, Cisco) pruning
- IEEE 802.1Q

## Goal

Remove a VLAN from trunks, cutting off the hosts that use it.

## How it works

The attacker sends VTP advertisements that claim a VLAN has no members on a segment. Trunks that trust the advertisement stop carrying that VLAN, and hosts behind them lose connectivity to it, without any change to their own configuration.

## What an auditor checks

- Check whether VTP pruning is enabled and whether VTP is used at all.
- Check the VTP domain and password configuration.
- Verify which VLANs each trunk carries.

## Defenses

- Disable VTP where static VLAN configuration is used.
- VTP passwords and version 3 where VTP is kept.
- Explicit VLAN allow lists on trunks.

## Related

The other techniques in this family are listed in the [family index](README.md).
