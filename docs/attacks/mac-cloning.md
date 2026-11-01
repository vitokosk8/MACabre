# MAC cloning

**Family**: MAC Address & CAM Table · **Priority**: P1

## What it abuses

Many networks use the MAC address as an identity for access: port security with a fixed or sticky address, MAC-based allow lists, and MAC authentication bypass on some switches. Any device that presents an allowed address is treated as an allowed device.

## Protocols involved

- **IEEE 802.1X**: port-based access control. It is the stronger alternative, because it authenticates the device, not just its address.
- **Port security and MAC authentication bypass**: vendor mechanisms that admit traffic by MAC address.
- **IEEE 802.3**: the Ethernet frame that carries the address.

## Goal

Get network access as an authorized device, by making the switch believe the attacker is that device.

## How it works

1. Read the MAC of an authorized device (for example from traffic or from a label).
2. Change the attacker's interface to that MAC. The whole host now sends with that identity, including its IP stack.
3. The port accepts the frames, and the attacker reaches the network as the authorized device.

Unlike spoofing, cloning changes every frame the host sends, not just a few forged ones.

## What an auditor checks

- Whether a port with a single allowed MAC drops frames from any other address.
- Whether a cloned address gets full access, or only what the device was allowed.
- Whether 802.1X is used, and whether it would stop a cloned MAC without a certificate.

## Defenses

- **802.1X with certificates**, so that the address alone is never enough.
- **Port security with violation shutdown**, and sticky addresses that alert on change.
- **Monitoring for duplicate addresses**, when the same MAC appears on two ports.

## Related

[MAC address spoofing](mac-address-spoofing.md) forges a few frames. Cloning takes over the whole identity.
