# DHCP NAK Injection

**Family**: DHCPv4 & DHCPv6 · **Priority**: P1

## What it abuses

A client that receives a DHCPNAK stops using its lease and restarts the discovery process. Because NAK messages are not authenticated, a device can send them to make clients drop their configuration, which causes repeated disconnects.

## Protocols involved

- DHCPv4 (RFC 2131, DHCPNAK)

## Goal

Make clients drop their configuration and restart, so that they disconnect repeatedly.

## How it works

The attacker sends a forged NAK to the client, using the server's address and the client's transaction. The client removes its lease and starts again. Repeating this keeps the client offline or moving between configurations.

## What an auditor checks

- Test whether a NAK from an unexpected source is accepted.
- Measure how long the client takes to recover.
- Check whether NAK messages are logged.

## Defenses

- DHCP snooping, which only passes server messages from trusted ports.
- Monitoring of NAK rates.
- Lease times that give clients some tolerance.

## Related

The other techniques in this family are listed in the [family index](README.md).
