# Multicast Flooding

**Family**: L2 Multicast & Broadcast · **Priority**: P1

## What it abuses

A switch that does not know which ports want a multicast group floods it to all ports of the VLAN. A stream of multicast frames for many groups therefore reaches every host, and saturates links where there are no receivers.

## Protocols involved

- IEEE 802.3 multicast addressing
- IGMP and MLD snooping

## Goal

Saturate links and hosts with multicast traffic that reaches every port.

## How it works

The attacker sends a high-rate stream to multicast groups that nobody has joined. A switch without snooping, or with snooping that does not learn the group, floods the stream to all ports. The audit measures the extra load on every port.

## What an auditor checks

- Send multicast to unjoined groups and count the ports that receive it.
- Check whether IGMP or MLD snooping is enabled.
- Check the rate limits for multicast.

## Defenses

- IGMP and MLD snooping with a querier.
- Rate limits for multicast on access ports.
- Monitoring of multicast volume per port.

## Related

The other techniques in this family are listed in the [family index](README.md).
