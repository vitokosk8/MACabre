# IPv6 RA Guard Evasion

**Family**: IPv6 Neighbor Discovery & SLAAC · **Priority**: P3

## What it abuses

RA Guard is a switch feature that drops RAs from untrusted ports. It must parse IPv6 extension headers and fragments to find the RA, and a packet that hides the RA in a form the filter does not parse can pass it.

## Protocols involved

- RA Guard (RFC 6105)
- IPv6 extension headers and fragmentation (RFC 8200)
- ICMPv6 Router Advertisement

## Goal

Send router advertisements that the switch filter does not parse, so that they reach the hosts.

## How it works

The attacker places the RA behind extension headers or in fragments, so the switch's filter does not see an RA at the expected position. A host that reassembles or parses the packet still processes the RA. The audit checks which forms the switch handles and which it lets through.

## What an auditor checks

- Test RA Guard with extension headers and fragments.
- Check the vendor's documented limits.
- Verify that unparsed packets are dropped, not forwarded.

## Defenses

- RA Guard with the latest parsing and drop-on-unknown behavior.
- Dropping of fragmented ICMPv6 on access ports where it is not needed.
- Monitoring of RA sources.

## Related

The other techniques in this family are listed in the [family index](README.md).
