# MKA Negotiation Disruption

**Family**: MACsec / IEEE 802.1AE · **Priority**: P3

## What it abuses

MKA exchanges MKPDUs on a schedule and keeps a live key agreement between peers. Corrupted or replayed MKPDUs make the agreement fail, and MACsec then stops protecting the link, or it stays down until the peers are reset.

## Protocols involved

- IEEE 802.1X-2010 (MKA)
- IEEE 802.1AE

## Goal

Break the key agreement, so that the link stops being protected or stays down.

## How it works

The attacker sends MKPDUs that do not match the current agreement, or it blocks the real ones. The peers cannot finish the key exchange, the secure channel does not come up, and the link carries no MACsec traffic, or it is held down by policy.

## What an auditor checks

- Inject corrupted MKPDUs in a lab and observe the peers.
- Check whether the link stays down or falls back to clear traffic.
- Check the logs for MKA failures.

## Defenses

- Strict MKA policy that stops the link instead of falling back.
- Monitoring of MKA state.
- Redundant paths for critical links.

## Related

The other techniques in this family are listed in the [family index](README.md).
