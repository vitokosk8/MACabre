# MLD Spoofing / Flooding

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

Multicast Listener Discovery (MLD) lets IPv6 routers learn which hosts want which multicast groups. Snooping switches use MLD reports to forward multicast only where it is needed, so forged or excessive reports change where multicast goes.

## Protocols involved

- Multicast Listener Discovery v1 and v2 (RFC 2710, RFC 3810)
- IPv6 multicast

## Goal

Receive multicast groups the attacker should not get, or disturb their forwarding.

## How it works

The attacker sends MLD reports for groups it does not need. A snooping switch adds the attacker's port to the group, and multicast for that group is delivered to it. A stream of reports also loads the switch and the snooping table.

## What an auditor checks

- Test whether a report from an access port changes forwarding.
- Measure the report rate the switch handles.
- Check whether MLD snooping and querier election are configured.

## Defenses

- MLD snooping with a fixed querier.
- Rate limits for MLD on access ports.
- Monitoring of group membership changes.

## Implementation status

Implemented in MACabre as its own panel entry. The module builds MLDv1 Reports (type 131) with a link-local source derived from the operator's MAC, hop limit 1 and a Hop-by-Hop Router Alert option, sent to the group's Ethernet address (33:33 plus the last 32 bits of the group). Spoofing is one Report; flooding is one Report per group over a range inside ff0e::/16, up to 8192 groups. Validated on Ubuntu (VM) with the lab in this branch's latest commit.

## Lab validation

Lab: `scripts/lab/mld_spoofing_flooding_lab.sh` (Linux, IPv6 kernel, one bridge with multicast snooping, namespaces). Control: the victim reports a legitimate group, which the bridge must learn on the victim's port. Spoof: the attacker reports one group it does not listen to, which the bridge must learn on the attacker's port. Flood: the attacker reports 4200 groups from ff0e::1000, then 1000 more. Saturation: the entry count on the attacker's port must stop growing between the two waves and sit close to the table size. The victim's control group must survive the flood. Test: the victim reports a new legitimate group, which must not be learned once the table is saturated. Exit 0 when all hold, 2 when the first control fails. The table does not always hold exactly MCAST_HASH_MAX entries, because hash collisions leave some slots unused; a first run on Ubuntu (VM) with a single 4200-group wave reached 4092 entries and did not learn the new group, which is why the check is a plateau. Validated on Ubuntu (VM): exit 0. The attacker's port held 4092 entries after both waves (flat), the victim's existing group stayed learned, and the victim's new group was not learned.

## Related

The other techniques in this family are listed in the [family index](README.md).
