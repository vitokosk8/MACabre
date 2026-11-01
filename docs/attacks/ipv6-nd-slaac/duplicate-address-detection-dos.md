# Duplicate Address Detection DoS

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P2

## What it abuses

Before using a new IPv6 address, a host runs Duplicate Address Detection (DAD) by sending an NS for it and waiting for an NA. A reply, even a forged one, makes the host think the address is taken, so the address is never configured.

## Protocols involved

- IPv6 Duplicate Address Detection (RFC 4862)
- ICMPv6 Neighbor Discovery (RFC 4861)

## Goal

Stop hosts from configuring their new addresses.

## How it works

When a host starts, it sends an NS for its tentative address. The attacker answers with an NA for that address. The host treats the address as duplicated and does not configure it. Repeated on every new host, this blocks address configuration on the segment.

## What an auditor checks

- Test whether a forged NA during DAD blocks configuration.
- Measure how many new hosts fail to configure an address.
- Check whether the host retries and how long it waits.

## Defenses

- Neighbor Discovery inspection.
- DHCPv6 with a fallback for hosts that fail DAD.
- Monitoring of DAD failures.

## Related

The other techniques in this family are listed in the [family index](README.md).
