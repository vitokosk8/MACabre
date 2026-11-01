# 802.1AS gPTP Manipulation

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

Generalized PTP (gPTP, IEEE 802.1AS) is the profile used for time-sensitive networks. Its peer-to-peer delay measurements compensate the delay of each link. A forged peer-delay response can change the measured delay and so the time error that the network accumulates.

## Protocols involved

- IEEE 802.1AS (gPTP, peer-to-peer delay mechanism)
- IEEE 802.1AS-2020

## Goal

Introduce a time error along the network, by faking path delay measurements.

## How it works

The attacker sends peer-delay responses that report a longer or shorter delay than the real one. The clocks compensate by the wrong amount, and the time error grows along the chain. The audit measures the error the attack introduces.

## What an auditor checks

- Check which ports exchange peer-delay messages.
- Test whether a forged response from an access port is accepted.
- Measure the time error with and without the forged responses.

## Defenses

- Peer-delay exchange restricted to the network's own links.
- Monitoring of path delay and time error.
- Physical separation of the time network.

## Related

The other techniques in this family are listed in the [family index](README.md).
