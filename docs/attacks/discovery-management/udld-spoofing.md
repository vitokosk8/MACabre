# UDLD Spoofing

**Family**: Discovery & Management Protocols · **Priority**: P3

## What it abuses

UDLD (Unidirectional Link Detection) finds links where traffic flows in one direction only. It exchanges echo messages between the ends, and a forged or replayed echo can make a broken link look healthy, or make a good link look broken.

## Protocols involved

- UDLD (Unidirectional Link Detection, Cisco, vendor protocol)

## Goal

Keep a broken link up, or bring a healthy one down, by faking UDLD messages.

## How it works

The attacker sends UDLD messages that carry the expected identity of the peer. If the switch accepts them, a broken link stays up and traffic is black-holed, or a healthy link is shut down when the echoes are dropped. The effect depends on the mode configured.

## What an auditor checks

- Test whether a UDLD message from an untrusted source is accepted.
- Check whether UDLD is in normal or aggressive mode.
- Check what the switch does after a unidirectional alarm.

## Defenses

- UDLD in aggressive mode on fiber links where it is supported.
- Monitoring of UDLD alarms.
- Physical link checks.

## Related

The other techniques in this family are listed in the [family index](README.md).
