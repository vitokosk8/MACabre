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

## Implementation status

The probe sends ARP requests from this segment for addresses outside it, and records which ones get an answer and the MAC that answers. It sends requests only and changes nothing on the router. The GUI panel exposes the sender address, the segment prefix and the targets. Targets inside the segment are refused, because a normal reply there is not proxy ARP.

## Lab validation

`scripts/lab/proxy_arp_abuse_lab.sh` puts the attacker on one segment, a host on another, and a Linux router between them. Phase 0 turns proxy ARP off on the router's segment-facing interface, and the probe gets no answer. Phase 1 turns it on, and the router answers for the host with its own MAC.

The lab shows the router's behavior on this Linux setup. Other routers have their own defaults and policies, so the audit must also run against the target device.
