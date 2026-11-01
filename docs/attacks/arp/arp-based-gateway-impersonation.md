# ARP-Based Gateway Impersonation

**Family**: ARP · **Priority**: P1

## What it abuses

Hosts trust the ARP entry for their default gateway, so the gateway's IP can be bound to another MAC address. A host that accepts the binding sends all its off-subnet traffic to the impersonator, which is a complete takeover of its outbound path.

## Protocols involved

- ARP (RFC 826)
- IPv4 default gateway selection

## Goal

Receive all off-subnet traffic of a host by taking the gateway's IP address in its ARP cache.

## How it works

The attacker sends ARP replies that claim the gateway's IP. The victim updates its cache, and every packet leaving the subnet goes to the attacker. The audit distinguishes this from simple ARP spoofing because the scope is all off-subnet traffic, not one destination.

## What an auditor checks

- Compare the gateway entry in each host's cache with the gateway's real MAC.
- Check whether hosts accept unsolicited replies for the gateway.
- Verify that the gateway's MAC change is detected and reported.

## Defenses

- Static ARP entries for the gateway on critical hosts.
- Dynamic ARP Inspection with trusted ports at the uplink.
- Monitoring for changes of the gateway MAC address.

## Related

The other techniques in this family are listed in the [family index](README.md).
