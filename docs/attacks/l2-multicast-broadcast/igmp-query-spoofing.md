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

## Related

The other techniques in this family are listed in the [family index](README.md).
