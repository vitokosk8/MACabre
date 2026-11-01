# 802.1X Identity Spoofing

**Family**: 802.1X / EAPOL / NAC · **Priority**: P2

## What it abuses

Early in EAP, the supplicant sends its identity, and the authenticator may use it to choose policy before authentication completes. An identity chosen by the attacker can select a different VLAN, a different group or a different server path.

## Protocols involved

- IEEE 802.1X
- EAP-Response/Identity (RFC 3748)
- RADIUS (RFC 2865)

## Goal

Obtain a port policy, by presenting an identity that the authenticator uses before authentication completes.

## How it works

The attacker presents an identity that belongs to a privileged group in the EAP identity response. If the authenticator forwards it to the server and applies a policy from the claim before the method is checked, the port can be placed in a policy the attacker should not reach.

## What an auditor checks

- Test whether the identity claim affects VLAN or policy before authentication.
- Check which identities are accepted for each port.
- Verify that the policy is decided by the method result.

## Defenses

- Policy decided only after successful authentication.
- Strong EAP methods with server certificate checks.
- Monitoring of identity claims that do not match the port.

## Related

The other techniques in this family are listed in the [family index](README.md).
