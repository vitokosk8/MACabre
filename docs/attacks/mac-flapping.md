# MAC flapping

**Family**: MAC Address & CAM Table · **Priority**: P1

## What it abuses

A learning switch believes the most recent frame it saw for a MAC address. If the same source MAC shows up on two ports in turn, the switch keeps moving the entry from one port to the other. Nothing in plain learning stops the moves.

## Protocols involved

- **IEEE 802.1D**: MAC learning and forwarding.
- **IEEE 802.3**: the frames that carry the source address.

## Goal

Disrupt the traffic addressed to one MAC address, which may go to the wrong port or be delayed while the entry flaps. It also stresses the switch's control plane, because every move is an update, and it floods the logs with alerts that can hide a real attack.

## How it works

1. Attach two interfaces to two ports of the same switch.
2. Send frames with the same source MAC from each interface, alternating between them.
3. Each frame makes the switch move the entry to the port it just came from.

## What an auditor checks

- How many times the switch moves the entry per second, and whether it logs the moves.
- Whether traffic to the flapping MAC is delivered, misdelivered or lost.
- Whether loop protection or flap detection reacts, and whether it disables the port or only logs.

## Defenses

- **MAC move detection** with logging, and alerts above a threshold.
- **Flap protection** that keeps the first port or disables the port after repeated moves.
- **Port security** with violation actions.

## Related

[MAC address spoofing](mac-address-spoofing.md) makes one move to redirect traffic. Flapping repeats the move forever.
