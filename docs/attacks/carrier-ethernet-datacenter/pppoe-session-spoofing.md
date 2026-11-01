# PPPoE Session Spoofing

**Family**: Carrier Ethernet & Data Center · **Priority**: P2

## What it abuses

After discovery, a PPPoE session is identified by a session ID that both ends use in every frame. Session data frames and the PADT message that ends a session are not authenticated, so a device that knows the session ID can inject data or end the session.

## Protocols involved

- PPPoE Session (RFC 2516, EtherType 0x8864)
- PPPoE Active Discovery Terminate (PADT)

## Goal

End another client's PPPoE session, or inject into it.

## How it works

The attacker learns or guesses the session ID of a client and sends a PADT from the concentrator's address. The client's session ends, and it must start discovery again. Frames with the session ID can also be injected to change the state of the session.

## What an auditor checks

- Test whether a PADT from another port ends a session.
- Check how session IDs are assigned.
- Check whether the concentrator logs PADT sources.

## Defenses

- Filters for PADT on access ports.
- Monitoring of session terminations.
- Access networks that separate PPPoE traffic per customer.

## Related

The other techniques in this family are listed in the [family index](README.md).
