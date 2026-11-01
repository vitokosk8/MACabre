# MAC flooding / CAM overflow

**Family**: MAC Address & CAM Table · **Priority**: P1

## What it abuses

A switch learns which MAC address lives on which port by looking at the source address of every frame it receives. It keeps that knowledge in a table of fixed size, the CAM table. When the table is full, a switch that fails open starts sending unknown unicast frames to every port, as if it were a hub.

## Protocols involved

- **IEEE 802.1D**: MAC learning and forwarding in bridges.
- **IEEE 802.3**: the Ethernet frames that carry the learning information.

## Goal

Fill the CAM table with fake source addresses, so that the switch floods unicast traffic to every port. An attacker on any port then sees frames that were addressed to other hosts. That is the confidentiality impact: a passive sniffer on a switched network.

## How it works

1. Generate frames with random source MACs and random unicast destinations.
2. The switch learns each random source on the attacker's port, and fills its table.
3. Once the table is full, frames for unknown destinations are flooded to all ports, including the attacker's.

The destination of the flooding frames is unknown to the switch by design, so it must flood them.

## What an auditor checks

- The CAM table size and how quickly the attack fills it.
- Whether the switch floods unknown unicast when it is full (fail open).
- Whether port security limits the number of learned MAC addresses per port.
- Whether storm control or unknown unicast rate limits are configured.

## Defenses

- **Port security** with a maximum MAC count and a violation action (shut down or restrict).
- **Storm control** and unknown unicast limits.
- **Monitoring** of MAC table growth and of port security violations.

## Related

[MAC flapping](mac-flapping.md) also abuses the learning table, but moves one MAC between ports instead of filling the table.
