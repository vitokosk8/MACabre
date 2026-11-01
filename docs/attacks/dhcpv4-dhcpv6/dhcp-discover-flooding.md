# DHCP Discover Flooding

**Family**: DHCPv4 & DHCPv6 · **Priority**: P1

## What it abuses

A DHCP server processes each DISCOVER and may reserve an address for it, which costs CPU and pool space. A high rate of DISCOVER messages from random clients keeps the server busy and fills its records.

## Protocols involved

- DHCPv4 (RFC 2131)

## Goal

Keep the server busy, and its records full, with a stream of DISCOVER messages.

## How it works

The attacker sends DISCOVER messages from many random MAC addresses. The server answers each one and keeps state for the offered addresses, so its processing and memory grow with the rate. Legitimate clients may wait longer or fail.

## What an auditor checks

- Measure the server's response time under a DISCOVER stream.
- Count the leases and offers reserved during the stream.
- Check whether the server rate-limits clients.

## Defenses

- DHCP snooping rate limits on access ports.
- Server rate limits and short offer timeouts.
- Port security to bound MAC addresses per port.

## Related

The other techniques in this family are listed in the [family index](README.md).
