# DHCPv6 Starvation

**Family**: DHCPv4 & DHCPv6 · **Priority**: P2

## What it abuses

DHCPv6 servers hand out addresses and prefixes from finite pools, as DHCPv4 servers do. Clients that send many SOLICIT messages with random identities can use up those pools, so that legitimate clients cannot get an address.

## Protocols involved

- DHCPv6 (RFC 8415)
- IPv6 multicast

## Goal

Empty the DHCPv6 address and prefix pools, so that legitimate clients get nothing.

## How it works

The attacker sends SOLICIT messages with random DUIDs, and completes the exchange so that the server commits the addresses. The pool empties, and new clients are refused. This follows the same logic as DHCPv4 starvation, with DHCPv6 messages.

## What an auditor checks

- Measure the pool size and the rate at which it empties.
- Check whether a legitimate client gets an address after the pool is full.
- Check per-client or per-port limits.

## Defenses

- DHCPv6 snooping and rate limits on access ports.
- Server limits per client identity.
- Monitoring of pool utilization.

## Implementation status

- Module: `src/macabre/attacks/dhcpv6_starvation.py`. It sends SOLICIT messages with random DUIDs and IA_NA identities to the All_DHCP_Relay_Agents_and_Servers group, and completes each exchange that gets an ADVERTISE with a REQUEST.
- GUI panel: "DHCPv6 Starvation".
- Status: 🔨 Implemented. Packet construction, parsing and the send loop are tested with Scapy. The lab is not validated yet.

## Lab validation

Not validated. `scripts/lab/dhcpv6_starvation_lab.sh` reports inconclusive: the development kernel has no IPv6 in network namespaces. The planned check is whether a legitimate client still gets an address once the attacker has used up the pool. A Linux machine with IPv6 is needed to run it.

## Related

The other techniques in this family are listed in the [family index](README.md).
