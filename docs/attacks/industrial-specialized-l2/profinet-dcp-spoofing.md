# PROFINET DCP Spoofing

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

PROFINET uses the Discovery and Configuration Protocol (DCP) on layer 2 to find devices and set their name and IP address. DCP Set requests are accepted from any device on the segment, so a host can rename or readdress a controller or a device.

## Protocols involved

- PROFINET DCP (EtherType 0x8892)
- PROFINET IO

## Goal

Rename or readdress devices in a control network.

## How it works

The attacker sends a DCP Set that changes the name or the IP address of a device. The device applies it and may stop communicating with its controller. Forged DCP responses can also make a tool show a false name or address for a device.

## What an auditor checks

- Test whether a DCP Set from an arbitrary host is accepted.
- Check which devices support a DCP lock or a permission setting.
- Check whether the change is logged.

## Defenses

- DCP filters on industrial switches.
- Segregation of the control network.
- Monitoring of DCP traffic.

## Related

The other techniques in this family are listed in the [family index](README.md).
