# PTP / IEEE 1588 Spoofing

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

The Precision Time Protocol (PTP, IEEE 1588) synchronizes clocks with timing messages. Those messages are not authenticated in the default profiles, so a device that sends forged Sync or Follow_Up messages can shift the time that clients believe.

## Protocols involved

- IEEE 1588 (PTP, layer 2 transport EtherType 0x88F7)
- IEEE 802.1AS (gPTP profile)

## Goal

Shift the clocks of the clients, by sending a false timing offset.

## How it works

The attacker sends Sync and Follow_Up messages with a chosen offset. A client that accepts them adjusts its clock to the offset. Systems that depend on accurate time, such as logging, sampled measurements or control loops, then operate on a wrong time base.

## What an auditor checks

- Check which PTP profile is used and whether authentication is enabled.
- Test whether a forged offset from an unexpected port is accepted.
- Check the clock offset alarms.

## Defenses

- PTP authentication where the profile supports it.
- Dedicated timing VLANs.
- Monitoring of clock offsets against a second source.

## Related

The other techniques in this family are listed in the [family index](README.md).
