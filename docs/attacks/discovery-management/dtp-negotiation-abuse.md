# DTP Negotiation Abuse

**Family**: Discovery & Management Protocols · **Priority**: P1

## What it abuses

Dynamic Trunking Protocol (DTP) negotiates whether a port becomes a trunk, based on the mode of both ends. The result depends on the mode configured on each port, so a port that accepts negotiation can end up as a trunk with a device the administrator did not intend.

## Protocols involved

- Dynamic Trunking Protocol (DTP, Cisco)
- IEEE 802.1Q

## Goal

Form a trunk on a port that should be an access port.

## How it works

The attacker sends DTP messages from an access port. Ports in dynamic auto or dynamic desirable mode negotiate and become trunks. Once a trunk is formed, the port carries the tagged traffic the attacker needs. The audit checks the modes, not only the trunk result.

## What an auditor checks

- Map the DTP mode of each port.
- Test whether a negotiation from an access port forms a trunk.
- Check which VLANs the resulting trunk carries.

## Defenses

- Access mode on user ports, with DTP disabled.
- Nonegotiate on all trunks.
- Monitoring of trunk formation.

## Related

The other techniques in this family are listed in the [family index](README.md).
