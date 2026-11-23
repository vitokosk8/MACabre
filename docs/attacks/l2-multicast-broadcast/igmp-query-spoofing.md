# IGMP Query Spoofing

**Family**: L2 Multicast & Broadcast · **Priority**: P2

## What it abuses

The IGMP querier periodically asks hosts which groups they want, and snooping switches use the queries to learn membership. Several queriers are elected on a segment, with the lowest address winning. A device that sends queries from a low address becomes the querier.

## Protocols involved

- IGMP (RFC 2236, RFC 3376)
- IGMP snooping querier election (RFC 4541)

## Goal

Become the querier, so that membership and forwarding follow the attacker's queries.

## How it works

The attacker sends queries from a low source address. The switches elect it as querier and stop using the real one. Membership tables then expire, and multicast stops reaching the real receivers, or reaches the attacker, depending on what it replies.

## What an auditor checks

- Test whether a query from an access port becomes the querier.
- Check which querier each switch elects.
- Check whether receivers lose traffic during the change.

## Defenses

- A fixed querier on the router.
- Querier election restricted to trusted ports.
- Monitoring of querier changes.

## Implementation

- Module: `src/macabre/attacks/igmp_query_spoofing.py`, panel `IGMP Query Spoofing`.
- IGMPv2 queries (type 0x11), general to 224.0.0.1 or group-specific, TTL 1, with the router-alert option. The source address is the operator's choice.
- The module only sends queries. It does not check which switch elects a querier.

## Lab validation

`scripts/lab/igmp_query_spoofing_lab.sh` puts the attacker and a receiver on one bridge with snooping on. It captures on the receiver's port with no query sent (baseline), then sends three general queries from a low source address and counts the queries the receiver captures. Exit 0 means the receiver captured every query sent and none before. This validates that queries from one port reach the other ports; it does not validate querier election. Not run on the VM yet.

## Related

The other techniques in this family are listed in the [family index](README.md).
