# MAB Bypass / MAC Spoofing

**Family**: 802.1X / EAPOL / NAC · **Priority**: P1

## What it abuses

MAC Authentication Bypass (MAB) lets devices that cannot run 802.1X authenticate with their MAC address, which the server checks against an allowed list. A MAC address is not a credential, so an attacker who copies an allowed address gets the access that device would have.

## Protocols involved

- MAC Authentication Bypass (vendor implementation)
- RADIUS (RFC 2865)
- IEEE 802.1X

## Goal

Obtain the access of an allowed device, by presenting its MAC address.

## How it works

The attacker sets its interface to the MAC address of a device on the allowed list. The authenticator forwards the address to the server as the user name, the server accepts it, and the port is authorized. The same result comes from MAC cloning, and the audit uses it to check that MAB is limited.

## What an auditor checks

- List the MAC addresses in the allowed list and where they are used.
- Test whether an allowed MAC from an unknown device is accepted.
- Check whether MAB is combined with another control.

## Defenses

- Limit MAB to devices that cannot run 802.1X, and to their known ports.
- Port security and a maximum of one MAC per MAB port.
- Monitoring of MAB sessions.

## Related

The other techniques in this family are listed in the [family index](README.md).
