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

## Implementation status

The module is passive. It captures for a set time and counts the unicast frames that are addressed to other hosts, and their destinations. It sends nothing, so it cannot fill the switch's table. The GUI panel exposes the listening time.

## Lab validation

`scripts/lab/unknown_unicast_flooding_lab.sh` builds a Linux bridge with a victim, a monitor and an idle attacker port. The victim sends unicast frames to a destination the switch has never learned. The listener on the monitor port should capture all of them. The lab also checks that the unknown destination is not learned, and that the victim's address is the only one learned on its port.

The lab shows that the switch floods unknown unicast frames to other ports on this bridge. It does not test rate limiting, storm control or table aging, which need a real switch.

## Related

The other techniques in this family are listed in the [family index](README.md).
