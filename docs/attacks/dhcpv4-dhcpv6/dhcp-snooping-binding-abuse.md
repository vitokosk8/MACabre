# DHCP Snooping Binding Abuse

**Family**: DHCPv4 & DHCPv6 · **Priority**: P3

## What it abuses

DHCP snooping builds a binding table that maps each client's MAC address, IP address, VLAN and port. Other protections, such as ARP inspection and IP source guard, depend on that table. Manipulating the table, through forged DHCP messages, weakens every control that uses it.

## Protocols involved

- DHCP snooping (vendor feature)
- Dynamic ARP Inspection
- IP Source Guard

## Goal

Create false bindings, so that the protections that depend on them accept the attacker's traffic.

## How it works

The attacker sends DHCP messages that create or change bindings for addresses it does not hold. The table then allows traffic from those addresses on the attacker's port, and ARP inspection accepts the matching packets. The attacker gains the identity of another client through the protections that should prevent it.

## What an auditor checks

- Test whether forged bindings are created from an untrusted port.
- Check that bindings expire and are checked against the port.
- Check which controls depend on the binding table.

## Defenses

- Snooping on all access ports, with only server ports trusted.
- Rate limits and maximum bindings per port.
- Monitoring of binding changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
