# MACsec Replay / PN Abuse

**Family**: MACsec / IEEE 802.1AE · **Priority**: P3

## What it abuses

MACsec frames carry a packet number (PN) that increases with each frame. A receiver in replay-protection mode drops frames with a PN it has already seen, which stops an attacker from repeating captured frames. The protection depends on the mode and on the window allowed.

## Protocols involved

- IEEE 802.1AE (MACsec packet number and replay protection)

## Goal

Repeat captured protected frames, where replay protection is weak.

## How it works

The attacker captures MACsec frames and sends them again. A receiver with replay protection drops them because their packet numbers are old. A receiver with a large window, or without replay protection, accepts some of them, which is the gap the audit checks.

## What an auditor checks

- Capture MACsec frames in a lab and replay them.
- Check the replay protection mode and the window.
- Check how the switch handles frames with an old PN.

## Defenses

- Replay protection enabled with a window of zero where supported.
- Rekey before the packet numbers approach their limit.
- Monitoring of replay drops.

## Related

The other techniques in this family are listed in the [family index](README.md).
