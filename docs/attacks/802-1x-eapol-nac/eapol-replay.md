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

## Implementation status

- Module: `src/macabre/attacks/eapol_replay.py` (captures the EAP responses one supplicant sends during a window, then sends them again).
- GUI panel: "EAPOL Replay".
- Status: 🔨 Implemented. In the lab, the replayed responses produced no activity: hostapd did not reopen the victim's session and FreeRADIUS got no new request, while a fresh EAPOL-Start from the same MAC did get a reaction. This configuration rejects replayed responses after authorization. Replay during an active exchange is not tested.

## Lab validation

`scripts/lab/eapol_replay_lab.sh` runs FreeRADIUS, hostapd in wired mode, and a wpa_supplicant victim with EAP-MD5 on a Linux bridge. The attacker captures the victim's two EAP responses during its authentication, then replays them after authorization. Control: one fresh EAPOL-Start from the victim's MAC, which the authenticator processes.

## Related

The other techniques in this family are listed in the [family index](README.md).
