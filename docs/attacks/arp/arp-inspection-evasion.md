# ARP Inspection Evasion

**Family**: ARP · **Priority**: P3

## What it abuses

Dynamic ARP Inspection checks ARP packets against the DHCP snooping binding table or static bindings. Its rules have edges: for example, which packets it checks, which ports are trusted, and how it treats addresses that are not bound. Those edges are what an audit tests.

## Protocols involved

- ARP (RFC 826)
- Dynamic ARP Inspection
- DHCP snooping binding table

## Goal

Send ARP traffic that the inspection does not catch, so that a binding can be forged anyway.

## How it works

The audit sends ARP packets that differ from the usual form, from ports that are trusted or unbound, or with addresses that are not in the binding table. It records which packets pass and which are dropped, to show gaps in the policy rather than to attack the device.

## What an auditor checks

- Map which ports are trusted and why.
- Test packets with addresses outside the binding table.
- Check that inspection covers both requests and replies.

## Defenses

- Inspection enabled on all access ports and VLANs that need it.
- Trusted ports only on uplinks to known devices.
- Static bindings for hosts that do not use DHCP.

## Related

The other techniques in this family are listed in the [family index](README.md).
