# Ethernet OAM Spoofing

**Family**: Discovery & Management Protocols · **Priority**: P3

## What it abuses

Ethernet OAM (IEEE 802.3ah) gives the two ends of a link a way to exchange status, events and loopback commands. A forged OAM frame can put the far end in loopback mode, or report link events that cause a shutdown.

## Protocols involved

- IEEE 802.3ah (Ethernet OAM)
- IEEE 802.3 slow protocols

## Goal

Put the far end of a link into loopback, or fake events that shut the link.

## How it works

The attacker sends OAM frames that request a remote loopback. The far end enters loopback mode and returns frames to the sender, which breaks forwarding on that link. Forged events can also trigger the peer to disable the port.

## What an auditor checks

- Test whether a loopback request is accepted from the peer.
- Check whether OAM is enabled on links that do not need it.
- Check whether loopback is logged.

## Defenses

- Disable OAM loopback on links that do not use it.
- Restrict OAM to point-to-point links.
- Monitoring of OAM events.

## Related

The other techniques in this family are listed in the [family index](README.md).
