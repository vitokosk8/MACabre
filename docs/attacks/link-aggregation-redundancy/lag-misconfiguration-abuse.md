# LAG Misconfiguration Abuse

**Family**: Link Aggregation & Redundancy · **Priority**: P2

## What it abuses

A link aggregate works only when both ends agree on its settings: mode, load balancing, timers and key. Mismatches can leave some members unused, or hash traffic in a way that concentrates it on one link. An attacker who can see the configuration can use the mismatch to cause loss or disclosure.

## Protocols involved

- IEEE 802.1AX (link aggregation)
- Vendor load-balancing hash policies

## Goal

Use a mismatch between the two ends to steer traffic or cause loss.

## How it works

The attacker finds an aggregate whose two ends disagree, for example on the mode or the hash. Traffic is then sent on fewer links than expected, or on a link that is not part of the bundle. The attacker can use the resulting imbalance to steer part of the traffic, or cause loss that is hard to explain.

## What an auditor checks

- Compare both ends of each aggregate.
- Check the load-balancing hash on each side.
- Test the effect of a mode mismatch on a lab bundle.

## Defenses

- Identical configuration on both ends, checked in the change process.
- Monitoring of member utilization.
- Alerts on aggregate state changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
