# Broadcast Storm

**Family**: L2 Multicast & Broadcast · **Priority**: P1

## What it abuses

A broadcast frame is flooded to every port of its VLAN, and Ethernet has no time-to-live field, so a broadcast that enters a loop goes around it forever. A broadcast storm saturates links and CPUs, and it can stop the whole VLAN.

## Protocols involved

- IEEE 802.3 broadcast delivery
- IEEE 802.1D loop behavior

## Goal

Saturate the VLAN with broadcast traffic, which stops legitimate traffic.

## How it works

The attacker sends broadcast frames at a high rate. Every switch floods them to all ports. If the topology has a loop, the frames multiply. Hosts and switches spend their capacity on broadcast processing, and legitimate traffic is delayed or lost.

## What an auditor checks

- Measure the rate at which the VLAN saturates.
- Check whether storm control is configured on access ports.
- Verify that the loop protection stops a storm.

## Defenses

- Storm control on access and trunk ports.
- Loop protection, such as BPDU-based detection.
- Limits on broadcast domain size.

## Related

The other techniques in this family are listed in the [family index](README.md).
