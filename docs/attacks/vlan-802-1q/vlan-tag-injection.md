# VLAN Tag Injection

**Family**: VLAN & IEEE 802.1Q · **Priority**: P1

## What it abuses

Tagged frames are meant to appear only on trunks. Some switches accept tags on access ports, and some pass tagged frames through without checking the VLAN membership of the port, which lets a host choose its own VLAN.

## Protocols involved

- IEEE 802.1Q tag format

## Goal

Choose the VLAN of a frame by inserting a tag that the access port should not accept.

## How it works

The attacker builds frames with an 802.1Q tag for a VLAN it does not belong to and sends them from an access port. If the switch keeps the tag and forwards the frame by it, the frame reaches the target VLAN. Whether this works depends entirely on how the switch treats tags on access ports.

## What an auditor checks

- Send tagged frames from an access port and see whether they are dropped.
- Check for configurations that trust tags on access ports.
- Verify that VLAN membership is enforced in forwarding, not only in configuration.

## Defenses

- Access ports that drop tagged frames.
- Strict VLAN membership checks.
- Monitoring of tagged frames on access ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
