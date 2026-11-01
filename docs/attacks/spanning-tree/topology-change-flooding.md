# Topology Change Flooding

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P1

## What it abuses

When the topology changes, switches send topology change notifications and flush their MAC tables faster than usual. Repeated topology changes keep the tables empty, so traffic is flooded more often, and the switches spend time on each change.

## Protocols involved

- IEEE 802.1D (topology change process)
- IEEE 802.1w

## Goal

Make switches flush their MAC tables over and over, so that traffic is flooded.

## How it works

The attacker sends BPDUs with the topology change flag set, repeatedly. Each one shortens the MAC table aging time for the switch. Frequent flushes cause flooding of traffic that would normally be forwarded to a single port, which increases the traffic any host can see.

## What an auditor checks

- Count topology change events in a time window.
- Measure how often MAC tables are flushed.
- Check whether the switch limits topology change processing.

## Defenses

- BPDU Guard on access ports.
- Monitoring of topology change counters.
- Rate limits on control traffic from access ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
