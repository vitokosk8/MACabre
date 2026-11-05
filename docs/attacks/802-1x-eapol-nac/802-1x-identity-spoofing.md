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

## Implementation status

- Module: `src/macabre/attacks/eapol_identity_spoofing.py` (starts an exchange per identity from a random or fixed MAC, waits for the identity request, and answers with the claimed identity, with no proof).
- GUI panel: "802.1X Identity Spoofing".
- Status: 🔨 Implemented. The lab validates that the authenticator forwards each claimed identity to RADIUS before any credential is checked (bob: 1 request, alice: 1 request). RADIUS answered each with an EAP-MD5 challenge, and granted no session. Identity spoofing against a RADIUS policy that accepts names without a credential is not tested.

## Lab validation

`scripts/lab/eapol_identity_spoofing_lab.sh` runs FreeRADIUS and hostapd in wired mode on a Linux bridge, with the attacker claiming bob (unknown) and alice (known, no password). Each identity uses its own random MAC, because hostapd ignores a second identity from a MAC while its first exchange is open. Control: an EAPOL-Start with no identity answer produces no RADIUS request.

## Related

The other techniques in this family are listed in the [family index](README.md).
