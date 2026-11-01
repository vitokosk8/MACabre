# Rogue PPPoE Access Concentrator

**Family**: Carrier Ethernet & Data Center · **Priority**: P2

## What it abuses

A client that wants a PPPoE session broadcasts a PADI and takes the first PADO it receives. The protocol does not authenticate the concentrator, so a device that answers first becomes the access concentrator that the client talks to.

## Protocols involved

- PPPoE Discovery (RFC 2516)
- PPP authentication (PAP, CHAP)

## Goal

Become the concentrator that clients connect to, and capture their authentication.

## How it works

The attacker answers the client's PADI with a PADO before the real concentrator does. The client selects the attacker and continues the session setup with it. If the client authenticates with PAP, its credentials are sent in clear to the attacker. With CHAP, the attacker can still capture challenge material for offline attempts.

## What an auditor checks

- Test whether a PADO from an unexpected port is accepted.
- Check which authentication method the clients use.
- Check whether the clients validate the concentrator name.

## Defenses

- Clients that restrict the concentrator by name or service.
- CHAP or stronger methods, never PAP.
- Discovery filters on the access switch.

## Related

The other techniques in this family are listed in the [family index](README.md).
