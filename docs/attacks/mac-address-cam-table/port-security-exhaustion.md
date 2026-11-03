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

## Implementation status

The module sends frames from one port, each with a new random source MAC, at a rate up to 100 frames per second. The GUI panel exposes the rate.

## Lab validation

`scripts/lab/port_security_exhaustion_lab.sh` builds a Linux bridge with an attacker port and a victim port. The victim sends one frame first, so the switch learns its MAC. The attacker then sends frames with new source MACs. The lab checks that the attacker's port learns one address per frame, and that the victim's entry stays on its own port.

A Linux bridge has no per-port MAC limit, so the lab cannot reach a violation action. The result shows what the sender controls, not what a switch does when its limit is reached. The status stays 🔨 Implemented until a real switch with port security configured is tested.

## Related

The other techniques in this family are listed in the [family index](README.md).
