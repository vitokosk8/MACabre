# L2 Loop Amplification

**Family**: L2 Multicast & Broadcast · **Priority**: P2

## What it abuses

A loop in a bridged network multiplies broadcast and multicast frames, because each switch floods a frame that comes back to it. The amplification depends on the number of loops and switches, so a single frame that enters a loop can produce many copies.

## Protocols involved

- IEEE 802.1D loop behavior
- IEEE 802.3 broadcast and multicast delivery

## Goal

Multiply one frame into many copies, to multiply the load it causes.

## How it works

The attacker sends one broadcast or multicast frame into a topology that contains a loop. Each switch floods it, and the copies multiply. The audit measures the amplification factor, which tells how much a single frame can cost the network.

## What an auditor checks

- Measure the copies produced by one frame in a lab loop.
- Check whether loop protection stops the amplification.
- Check the storm control thresholds.

## Defenses

- Loop protection and blocked redundant paths.
- Storm control on all ports.
- Monitoring of broadcast and multicast volume.

## Related

The other techniques in this family are listed in the [family index](README.md).
