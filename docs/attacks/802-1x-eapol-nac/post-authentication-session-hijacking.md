# Post-Authentication Session Hijacking

**Family**: 802.1X / EAPOL / NAC · **Priority**: P3

## What it abuses

Once a supplicant is authorized, the port trusts the traffic that comes from its MAC address. An attacker that takes over that address after authorization, usually by cloning it or by waiting for the host to go quiet, inherits the authorization without authenticating.

## Protocols involved

- IEEE 802.1X
- MAC learning on the authenticated port

## Goal

Use an authorized port, by taking the MAC address of the host that authenticated.

## How it works

The authenticated host goes offline or is powered down. The attacker connects to the same port, takes its MAC address, and sends traffic. The switch still treats the port as authorized, and the attacker uses the session until the authorization expires or the real host returns.

## What an auditor checks

- Test whether a second host with the same MAC on the port keeps the authorization.
- Check the reauthentication period and the aging of the MAC.
- Check whether the switch logs the MAC change.

## Defenses

- Periodic reauthentication with short intervals.
- MACsec, which binds frames to a key.
- Port security and monitoring of MAC changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
