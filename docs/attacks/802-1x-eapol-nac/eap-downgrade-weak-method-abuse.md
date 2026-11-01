# EAP Downgrade / Weak Method Abuse

**Family**: 802.1X / EAPOL / NAC · **Priority**: P3

## What it abuses

EAP is a framework with many methods, and an authenticator that offers a weak method, or accepts a downgrade, lets an attacker authenticate with a method that leaks or can be cracked. The attacker can then obtain the credential of a legitimate user.

## Protocols involved

- EAP (RFC 3748)
- EAP-MD5, EAP-PAP and other legacy methods
- RADIUS (RFC 2865)

## Goal

Make the exchange use a weak method, so that the attacker obtains a credential it can attack offline.

## How it works

The attacker answers the EAP method proposal with a legacy method, such as one that sends a hashed or plaintext credential. The authenticator accepts it, and the attacker captures material it can use offline. The attack depends on the authenticator allowing legacy methods.

## What an auditor checks

- List the methods the server accepts.
- Test whether a client can be made to use a legacy method.
- Check whether the server reports the method used in its logs.

## Defenses

- Disable legacy methods on the server.
- Require server certificate validation on clients.
- Monitoring of the methods used on each port.

## Related

The other techniques in this family are listed in the [family index](README.md).
