# MACsec Key Rotation Disruption

**Family**: MACsec / IEEE 802.1AE · **Priority**: P3

## What it abuses

MACsec uses short-lived secure association keys (SAK) that are rotated by the MKA agreement. Disrupting the rotation leaves the peers with keys that do not match, or with an expired key, so the link drops until a new agreement completes.

## Protocols involved

- IEEE 802.1X-2010 (MKA, SAK distribution)
- IEEE 802.1AE

## Goal

Break key rotation, so that the link drops and stays down.

## How it works

The attacker interferes with the MKA messages that carry the new SAK. One peer switches to a key the other has not accepted, and frames fail their integrity check. The link is down until the peers agree again, and repeated disruption keeps it down.

## What an auditor checks

- Measure the rotation interval.
- Disrupt a rotation in a lab and time the recovery.
- Check whether the peers log the mismatch.

## Defenses

- Rotation intervals that match the risk.
- Automatic recovery in the MKA implementation.
- Monitoring of key age and rotation failures.

## Related

The other techniques in this family are listed in the [family index](README.md).
