# HSR / PRP Redundancy Abuse

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

High-availability Seamless Redundancy (HSR, IEC 62439-3) and Parallel Redundancy Protocol (PRP) send each frame over two paths and remove duplicates at the receiver, using a redundancy tag. Forged or altered redundancy tags can make receivers drop valid frames or accept duplicates.

## Protocols involved

- IEC 62439-3 (HSR and PRP)
- IEEE 802.3 frames with a redundancy tag

## Goal

Make receivers discard valid frames, or accept forged ones, by manipulating redundancy tags.

## How it works

The attacker sends frames with redundancy tags that match the sequence numbers of valid traffic. The receiver discards the real frame as a duplicate, or accepts the forged one as the first copy. The redundancy then hides the loss, so the effect can go unnoticed for some time.

## What an auditor checks

- Check the redundancy tags and the duplicate handling of each device.
- Test forged tags in a lab.
- Check whether duplicate discards are counted and reported.

## Defenses

- Redundancy devices that count and report discarded duplicates.
- Segregation of the two networks.
- Monitoring of redundancy statistics.

## Related

The other techniques in this family are listed in the [family index](README.md).
