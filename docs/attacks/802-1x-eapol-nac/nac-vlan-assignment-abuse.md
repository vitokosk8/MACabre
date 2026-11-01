# NAC VLAN Assignment Abuse

**Family**: 802.1X / EAPOL / NAC · **Priority**: P3

## What it abuses

Authentication servers can assign a VLAN to a supplicant after it authenticates, using RADIUS attributes. A misconfigured or spoofed assignment places the client in a VLAN it should not reach, and the switch enforces the placement without further checks.

## Protocols involved

- RADIUS tunnel attributes for VLAN assignment (RFC 3580)
- IEEE 802.1X
- IEEE 802.1Q

## Goal

Obtain a VLAN assignment the attacker should not receive, through a group, an identity or a fallback.

## How it works

The attacker gets the authentication server to assign a VLAN through a group or identity it controls, or uses a fallback VLAN that is more permissive than intended. The client then sits in that VLAN and has the access the assignment gives.

## What an auditor checks

- List the VLAN assignments for each group.
- Check the fallback and guest VLANs.
- Test whether a client in the guest VLAN can reach protected VLANs.

## Defenses

- Explicit assignment rules with a deny default.
- Review fallback and guest VLAN access.
- Monitoring of VLAN assignments.

## Related

The other techniques in this family are listed in the [family index](README.md).
