# PAgP Spoofing

**Family**: Link Aggregation & Redundancy · **Priority**: P3

## What it abuses

Port Aggregation Protocol (PAgP) is the Cisco negotiation protocol for EtherChannel, equivalent in purpose to LACP. PAgP messages are not authenticated, so a device can send them and take part in the bundle negotiation.

## Protocols involved

- Port Aggregation Protocol (PAgP, Cisco)

## Goal

Form a channel with the attacker's port, so that traffic hashed onto it is delivered there.

## How it works

The attacker sends PAgP messages that advertise a partner. The switch forms a channel with the attacker's port, and traffic hashed onto that channel can reach the attacker. The effect matches LACP spoofing, with the Cisco protocol.

## What an auditor checks

- Test whether PAgP from an access port forms a channel.
- Check the PAgP mode of each port.
- Check whether a channel change is logged.

## Defenses

- PAgP only on ports configured for it, or disabled on access ports.
- Monitoring of channel membership.
- Port security on channel members.

## Related

The other techniques in this family are listed in the [family index](README.md).
