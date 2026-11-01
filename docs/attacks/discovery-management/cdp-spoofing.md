# CDP Spoofing

**Family**: Discovery & Management Protocols · **Priority**: P1

## What it abuses

Cisco Discovery Protocol (CDP) announces each device's identity, platform, port and addresses to its neighbors. The announcements are not authenticated, so a host can announce itself as a switch or a phone, and neighbors record that identity.

## Protocols involved

- Cisco Discovery Protocol (CDP, proprietary, SNAP encapsulated)

## Goal

Appear as a trusted network device, to be believed by tools or to change the voice VLAN of phones.

## How it works

The attacker sends CDP advertisements that claim to be a switch or a voice device, with a chosen address and VLAN. The switch stores the neighbor entry, and tools that read it report the false device. Phones and other devices that use CDP for VLAN settings may also act on the advertisement.

## What an auditor checks

- Test whether a CDP advertisement from an access port creates a neighbor entry.
- Check whether CDP VLAN information is applied.
- Check whether the switch reports the neighbor in its inventory.

## Defenses

- Disable CDP on access ports where it is not needed.
- Use LLDP-MED or a secure voice configuration.
- Monitoring of neighbor changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
