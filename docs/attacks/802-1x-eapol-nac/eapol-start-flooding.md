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

## Related

The other techniques in this family are listed in the [family index](README.md).
