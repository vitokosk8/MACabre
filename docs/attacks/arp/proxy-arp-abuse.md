# Proxy ARP Abuse

**Family**: ARP · **Priority**: P2

## What it abuses

Proxy ARP lets a router answer ARP requests on behalf of hosts on another network. When it is enabled where it is not needed, any host can use the router to reach addresses it should not, and the router can be made to answer for addresses it does not own.

## Protocols involved

- ARP (RFC 826)
- Proxy ARP behavior of routers

## Goal

Reach addresses across a segment boundary, using a router that answers on behalf of other networks.

## How it works

A host asks for an address on another subnet. A router with proxy ARP enabled replies with its own MAC address, and the host sends traffic to the router, which forwards it. An attacker can use this to bypass segment boundaries, or to get the router to answer for addresses it should not.

## What an auditor checks

- Check whether proxy ARP is enabled on each interface.
- Test which addresses the router answers for when asked from an access port.
- Confirm that segmentation policies still hold with proxy ARP.

## Defenses

- Disable proxy ARP where routing is used instead.
- Restrict proxy ARP to the segments that need it.
- Private VLANs or port isolation to block host-to-host traffic.

## Related

The other techniques in this family are listed in the [family index](README.md).
