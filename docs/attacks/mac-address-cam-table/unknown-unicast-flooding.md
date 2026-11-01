# Unknown Unicast Flooding

**Family**: MAC Address & CAM Table · **Priority**: P2

## What it abuses

A switch that does not know the port of a destination MAC address sends the frame to every port in the VLAN. That is normal behavior, but it means any unknown or aged-out destination is copied to all hosts, which is the basis for passive sniffing on a switched network.

## Protocols involved

- IEEE 802.1D forwarding rules
- IEEE 802.3 frames

## Goal

Receive unicast traffic addressed to other hosts, using the flooding that happens when the destination is unknown.

## How it works

Unicast frames for addresses that are not in the table, or that have aged out, are flooded to all ports. An attacker on any port can see that traffic. The audit measures how often destinations are unknown, which happens after table aging, after a flood, or when a host is silent for a while.

## What an auditor checks

- Measure how many unknown unicast frames the VLAN produces during normal operation.
- Check the table aging time and the table size.
- Check whether the switch rate-limits unknown unicast traffic.

## Defenses

- Unknown unicast rate limiting or storm control.
- Adequate table size and aging times.
- Port security to bound the number of learned addresses.

## Related

The other techniques in this family are listed in the [family index](README.md).
