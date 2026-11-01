# EAP Relay / Evil Authenticator

**Family**: 802.1X / EAPOL / NAC · **Priority**: P3

## What it abuses

EAP exchanges can be relayed: an attacker sits between a supplicant and a real authenticator and forwards the exchange, or it presents a fake authenticator that collects credentials from a supplicant that does not check the server.

## Protocols involved

- EAP (RFC 3748)
- IEEE 802.1X
- RADIUS (RFC 2865)

## Goal

Pass authentication through the attacker, or collect credentials from a client that does not check the server.

## How it works

The attacker forwards EAP messages from a supplicant to the real authenticator and back, so the supplicant believes it is authenticated through a path it controls. Or the attacker offers its own authenticator and records what the supplicant sends. Clients that do not validate the server certificate are exposed.

## What an auditor checks

- Test whether clients validate the authentication server.
- Check whether an exchange can be relayed over another link.
- Check the server certificate configuration.

## Defenses

- Mandatory server certificate validation on supplicants.
- Strong EAP methods with mutual authentication.
- Monitoring of authentication servers.

## Related

The other techniques in this family are listed in the [family index](README.md).
