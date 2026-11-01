# DHCP Release Spoofing

**Family**: DHCPv4 & DHCPv6 · **Priority**: P2

## What it abuses

A client sends DHCPRELEASE to tell the server it no longer needs its lease. The server frees the address, and it can give it to someone else. A forged release frees an address that is still in use.

## Protocols involved

- DHCPv4 (RFC 2131, DHCPRELEASE)

## Goal

Free an address that is still in use, so that another client receives it and a conflict follows.

## How it works

The attacker sends a release that carries the victim's client identity and address. The server removes the lease, and another client may be given the address while the victim still uses it. This produces an address conflict and disrupts both hosts.

## What an auditor checks

- Test whether a release from a different port is accepted.
- Check whether the server verifies the client identity in releases.
- Check how often a released address is reassigned.

## Defenses

- DHCP snooping that checks the port of each client against its lease.
- Monitoring of lease and address conflicts.
- Duplicate address detection on clients.

## Related

The other techniques in this family are listed in the [family index](README.md).
