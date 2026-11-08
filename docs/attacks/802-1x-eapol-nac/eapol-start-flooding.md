# EAPOL Start Flooding

**Family**: 802.1X / EAPOL / NAC · **Priority**: P2

## What it abuses

802.1X authenticators wait for an EAPOL-Start from a supplicant before they begin an authentication session. Each Start opens state on the authenticator, so a stream of Start frames consumes sessions and processing.

## Protocols involved

- IEEE 802.1X (EAPOL, EAP over LAN)
- EAP (RFC 3748)

## Goal

Consume the authenticator's sessions with a flood of authentication starts.

## How it works

The attacker sends EAPOL-Start frames from many MAC addresses, or repeatedly from one, so the authenticator opens a session for each. Its session table fills and its processing grows, and legitimate supplicants may wait or fail to authenticate.

## What an auditor checks

- Count the sessions opened under a Start stream.
- Check the authenticator's session limit and timeout.
- Check whether a Start from an unknown MAC is rate-limited.

## Defenses

- Rate limits for EAPOL on access ports.
- Port security to bound MAC addresses per port.
- Monitoring of session counts.

## Implementation status

- Module: `src/macabre/attacks/eapol_start_flooding.py` (sends EAPOL-Start frames from random or fixed supplicant MACs to the PAE group address, with no EAP exchange).
- GUI panel: "EAPOL Start Flooding".
- Status: 🔨 Implemented. The lab validates that a hostapd wired authenticator answers each EAPOL-Start in a flood with an EAP-Request/Identity (200 of 200 supplicants), and that a legitimate supplicant still gets one afterwards. It does not measure authenticator state or limits.

## Lab validation

`scripts/lab/eapol_start_flooding_lab.sh` runs hostapd in wired mode on a Linux bridge, with no RADIUS server, and a probe supplicant. The bridge forwards the PAE group address (`group_fwd_mask 8`). Baseline: the probe gets an identity request. Flood: 200 supplicants from 200 EAPOL-Start frames each get one; hostapd also retransmits, which the lab reports separately.

## Related

The other techniques in this family are listed in the [family index](README.md).
