# 802.1ah PBB Encapsulation Abuse

**Family**: Carrier Ethernet & Data Center · **Priority**: P3

## What it abuses

Provider Backbone Bridging (IEEE 802.1ah) encapsulates customer frames in a backbone frame with new source and destination MAC addresses. The backbone switches learn only backbone addresses, and the service identifier (I-SID) decides which service the frame belongs to.

## Protocols involved

- IEEE 802.1ah (PBB, MAC-in-MAC)
- IEEE 802.1ad

## Goal

Deliver customer traffic in another customer's service, by controlling the backbone fields.

## How it works

The attacker sends customer frames that the edge encapsulates with the wrong service identifier, or that try to carry a backbone address of another customer. If the edge does not set those fields, the frame is delivered in another customer's service.

## What an auditor checks

- Check the I-SID mapping on each edge port.
- Test whether a customer can choose its I-SID.
- Verify that backbone addresses are set by the edge only.

## Defenses

- I-SID set by the edge from the port configuration.
- Separate backbone address spaces per service.
- Monitoring of I-SID mappings.

## Related

The other techniques in this family are listed in the [family index](README.md).
