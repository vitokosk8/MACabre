# LLDP-MED Policy Spoofing

**Family**: Discovery & Management Protocols · **Priority**: P2

## What it abuses

LLDP-MED adds media-specific extensions to LLDP, such as a network policy that gives a voice VLAN, a priority and a DSCP value to a phone. A device that announces a false policy can change where a phone sends its traffic.

## Protocols involved

- ANSI/TIA-1057 (LLDP-MED)
- IEEE 802.1AB (LLDP)
- IEEE 802.1Q

## Goal

Move a phone's traffic into another VLAN or priority.

## How it works

The attacker sends an LLDP-MED frame with a network policy that names a voice VLAN or a DSCP value. The endpoint applies it and sends its traffic on the new VLAN or priority. This can move traffic into a VLAN the attacker should not reach, or change quality of service for other traffic.

## What an auditor checks

- Test whether an LLDP-MED policy from an access port is applied.
- Check which VLAN and priority the endpoint uses.
- Verify that policies are accepted only from the switch.

## Defenses

- Accept LLDP-MED policies only on trusted ports.
- Static voice VLAN configuration.
- Monitoring of policy changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
