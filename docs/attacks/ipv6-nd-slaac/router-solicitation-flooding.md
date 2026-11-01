# Router Solicitation Flooding

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

Hosts send Router Solicitations (RS) to ask for RAs. Routers process each RS and reply, so a stream of RS messages from random addresses costs the routers CPU and can crowd out real traffic.

## Protocols involved

- ICMPv6 Router Solicitation (RFC 4861)

## Goal

Load the routers with solicitations and with their replies.

## How it works

The attacker sends RS messages at a high rate, sometimes from random sources. The router answers each one with an RA, which is multicast or unicast, and its processing and output grow with the rate. The legitimate hosts see slower responses or lost RAs.

## What an auditor checks

- Measure the router's response rate to an RS stream.
- Check whether the router rate-limits RA responses.
- Check whether RS from access ports is restricted.

## Defenses

- Rate limits for RS and RA on routers.
- RA Guard and access port limits.
- Monitoring of RS rates.

## Related

The other techniques in this family are listed in the [family index](README.md).
