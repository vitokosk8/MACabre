# Port Security Exhaustion

**Family**: MAC Address & CAM Table · **Priority**: P2

## What it abuses

Port security limits how many MAC addresses a port may learn. Its counters and limits are finite and shared, so filling them with fake addresses can block the legitimate host on that port, or cause the switch to shut the port.

## Protocols involved

- IEEE 802.1D
- Vendor port security (maximum MAC count, violation modes)

## Goal

Use up a port's learning limit so that the legitimate host is blocked, or the port is shut down.

## How it works

Frames with many different source addresses arrive on one port. The port learns each one until the configured maximum is reached. After that, the violation action applies: frames are dropped, the port is restricted, or the port is shut down. The legitimate host may then lose connectivity, even though it never sent anything wrong.

## What an auditor checks

- Verify the configured maximum and the violation action on each access port.
- Check whether the legitimate host recovers after the violation, and how long that takes.
- Check that violations are logged with enough detail to find the port.

## Defenses

- Sticky MAC learning with a sensible limit per port.
- Violation action that restricts traffic instead of shutting the port, when availability matters.
- Monitoring of violation counters.

## Related

The other techniques in this family are listed in the [family index](README.md).
