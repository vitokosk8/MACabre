# MACsec SCI Spoofing

**Family**: MACsec / IEEE 802.1AE · **Priority**: P3

## What it abuses

Each MACsec secure channel is identified by a Secure Channel Identifier (SCI), made of a MAC address and a port number. The receiver uses the SCI in each frame to find the secure association. An attacker that uses another SCI causes the receiver to look up the wrong association.

## Protocols involved

- IEEE 802.1AE (SCI in the SecTAG)

## Goal

Make the receiver use the wrong secure association, or accept frames from another channel.

## How it works

The attacker sends frames with an SCI that belongs to another peer. The receiver either drops them, which is correct, or uses the other peer's association and fails their integrity check. The audit checks that SCI lookups are strict and that unknown SCIs are logged.

## What an auditor checks

- Test frames with an SCI that matches no association.
- Check whether a known SCI from another port is accepted.
- Check the logs for SCI mismatches.

## Defenses

- Strict SCI matching on the receiver.
- Monitoring of unknown SCIs.
- Unique CAKs per link.

## Related

The other techniques in this family are listed in the [family index](README.md).
