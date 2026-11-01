# TCN Spoofing

**Family**: Spanning Tree (STP / RSTP / MSTP / PVST+) · **Priority**: P1

## What it abuses

A topology change notification (TCN) is a message a switch sends toward the root when it detects a change. Because TCNs are not authenticated, a device can send them, and the switches flush their tables as if a real change had occurred.

## Protocols involved

- IEEE 802.1D (TCN BPDUs)

## Goal

Force MAC table flushes by sending false topology change notifications.

## How it works

The attacker sends TCN BPDUs at a chosen rate. Each switch that receives a TCN flushes its table for the affected ports, and forwards the notification toward the root. The effect is the same as a real change, without any change in the network.

## What an auditor checks

- Test whether TCNs from an access port cause a flush.
- Count flushes produced by the test.
- Check whether the switch logs TCN sources.

## Defenses

- BPDU Guard, so that access ports cannot send BPDUs at all.
- Shorter TCN propagation scope where supported.
- Monitoring of TCN counts.

## Related

The other techniques in this family are listed in the [family index](README.md).
