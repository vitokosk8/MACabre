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

## Implementation status

Implemented in MACabre as its own panel entry. The module builds the Router Advertisement in three forms: plain (the control), behind a Destination Options header with PadN, and split across two IPv6 fragments (the first holds only the first 8 octets of the ICMPv6 message, so a filter that reads one fragment never sees the Prefix Information option). It sends from the operator's MAC to the all-nodes group with hop limit 255. The module reports what it sent; whether a switch drops the forms is not measured by the module.

## Lab validation

Lab: `scripts/lab/ipv6_ra_guard_evasion_lab.sh` (Linux, IPv6 kernel, one bridge with multicast snooping off, namespaces). The lab checks the host side only: a Linux bridge does not implement RA Guard. Control: a plain RA must make the victim take the attacker as default router and configure an address in 2001:db8:bad::/64. Then the same RA is sent behind a Destination Options header, and split across two fragments. Exit 0 when the control holds and the host accepts both evasive forms. Pending validation on Ubuntu (VM). Switch RA Guard implementations need the target switch.

## Related

The other techniques in this family are listed in the [family index](README.md).
