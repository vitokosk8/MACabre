# Unknown Multicast Flooding

**Family**: L2 Multicast & Broadcast · **Priority**: P2

## What it abuses

A switch that receives a multicast frame for a group that is not in its snooping table floods it to the VLAN. This is the multicast form of unknown unicast flooding, and it reaches every port that might not want the group.

## Protocols involved

- IGMP and MLD snooping
- IEEE 802.3 multicast addressing

## Goal

Reach traffic for groups nobody joined, which the switch floods to every port.

## How it works

The attacker sends frames for groups that nobody has joined. Each one is flooded to all ports, so every host sees traffic it did not ask for. The volume depends on the rate the attacker chooses, and the switch processes each one.

## What an auditor checks

- Send frames to unknown groups and count the ports that receive them.
- Check whether unknown multicast can be dropped instead of flooded.
- Check the rate limits.

## Defenses

- Drop unknown multicast where the design allows it.
- Rate limits for multicast on access ports.
- Monitoring of unknown multicast.

## Implementation status

Implemented in MACabre as its own panel entry, "Unknown Multicast Flooding". It uses the multicast flooding sender with the same stream to groups nobody joined. Real switches are not tested.

## Lab validation

Lab: `scripts/lab/multicast_flooding_lab.sh`, the same lab as Multicast flooding. A receiver that joined no group gets the flood to unknown groups (flood phase). With flooding of unknown multicast turned off on its port, it gets none (control). Exit 0 when both hold.

## Related

The other techniques in this family are listed in the [family index](README.md).
