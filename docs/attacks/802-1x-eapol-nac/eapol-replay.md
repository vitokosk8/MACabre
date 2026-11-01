# EAPOL Replay

**Family**: 802.1X / EAPOL / NAC · **Priority**: P2

## What it abuses

EAP exchanges carry nonces and identifiers that let the peers detect replayed messages. If an authenticator or supplicant does not check these, captured EAPOL frames can be sent again to repeat an earlier exchange.

## Protocols involved

- IEEE 802.1X (EAPOL)
- EAP methods and their replay protection (RFC 3748)

## Goal

Repeat an earlier authentication exchange with captured frames.

## How it works

The attacker records EAPOL frames from a legitimate exchange and sends them again later. A peer that does not check identifiers or nonces processes them, which can repeat a state transition or trigger a new session with stale values.

## What an auditor checks

- Capture a legitimate exchange and replay it.
- Check whether the peers reject the replayed identifiers.
- Check the authenticator's handling of duplicate frames.

## Defenses

- Authenticator and supplicant that check identifiers and nonces.
- Current EAP methods with replay protection.
- Monitoring of duplicate EAP frames.

## Related

The other techniques in this family are listed in the [family index](README.md).
