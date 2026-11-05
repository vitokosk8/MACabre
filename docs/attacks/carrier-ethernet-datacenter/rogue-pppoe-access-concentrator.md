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

## Implementation status

- Module: `src/macabre/attacks/rogue_pppoe_access_concentrator.py` (answers PADI with a PADO carrying a new AC-Cookie, and answers a PADR only when it carries that cookie with a PADS).
- GUI panel: "Rogue PPPoE Access Concentrator".
- Status: 🔨 Implemented. The lab validates the handshake: a client that chooses the rogue's PADO completes PADR/PADS with it (10 of 10 trials). It also measures the race on this host: the rogue's PADO came first in 0 of 10 trials, because the legitimate concentrator answered faster. The lab does not validate PAP or CHAP capture, since no PPP session runs.

## Lab validation

`scripts/lab/rogue_pppoe_access_concentrator_lab.sh` runs `pppoe-server` and the rogue on a Linux bridge with a probe client, in three phases: a control with the legitimate server only; a race in which the client takes the first PADO; and a handshake in which the client takes the rogue's PADO. The race result depends on timing, so the lab reports it without forcing it.

## Related

The other techniques in this family are listed in the [family index](README.md).
