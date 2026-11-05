# EAPOL Logoff Spoofing

**Family**: 802.1X / EAPOL / NAC · **Priority**: P2

## What it abuses

An EAPOL-Logoff tells the authenticator that a supplicant has left, and the port returns to the unauthorized state. The message is not authenticated, so a forged logoff ends another host's session.

## Protocols involved

- IEEE 802.1X (EAPOL-Logoff)

## Goal

End another host's authorized session, and keep that host offline.

## How it works

The attacker sends an EAPOL-Logoff with the victim's source address. The authenticator removes the victim's authorization and the port drops its traffic until the host authenticates again. Repeating the logoff keeps the victim offline.

## What an auditor checks

- Test whether a logoff from another port is accepted.
- Check how fast a logged-off host can re-authenticate.
- Verify that logoffs are logged with their source.

## Defenses

- Authenticator checks that the logoff comes from the authorized port.
- Monitoring of logoffs.
- MACsec for ports where session integrity matters.

## Implementation status

- Module: `src/macabre/attacks/eapol_logoff_spoofing.py` (sends EAPOL-Logoff frames that claim the MAC the operator gives).
- GUI panel: "EAPOL Logoff Spoofing".
- Status: 🔨 Implemented. The lab validates that hostapd deauthorizes an authenticated supplicant after logoffs that claim its MAC (1 disconnect), and that logoffs from another MAC or no logoff leave it authorized.

## Lab validation

`scripts/lab/eapol_logoff_spoofing_lab.sh` runs FreeRADIUS, hostapd in wired mode, and a wpa_supplicant victim with EAP-MD5 on a Linux bridge. Control: no disconnects during a quiet wait, and none after logoffs from the attacker's own MAC. Attack: the victim is disconnected after logoffs that claim its MAC.

## Related

The other techniques in this family are listed in the [family index](README.md).
