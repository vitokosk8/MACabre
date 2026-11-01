# DHCP Offer Flooding

**Family**: DHCPv4 & DHCPv6 · **Priority**: P1

## What it abuses

A client that receives many OFFERs has to process each one, and some clients keep all of them for selection. A stream of fake offers can overload the client, or make it pick an offer that the attacker controls.

## Protocols involved

- DHCPv4 (RFC 2131)

## Goal

Overload clients, or make them choose an offer controlled by the attacker.

## How it works

The attacker sends OFFERs in response to DISCOVER messages, or sends unsolicited offers, so that the client has many to select from. Depending on the client, it may process them slowly, or pick the one that arrives first with the most favorable values.

## What an auditor checks

- Test how the client behaves with many offers.
- Check which offer the client selects.
- Check whether the server's offers still arrive in time.

## Defenses

- DHCP snooping on untrusted ports.
- Rate limits for DHCP on access ports.
- Monitoring of OFFER rates.

## Related

The other techniques in this family are listed in the [family index](README.md).
