# DHCP starvation

**Family**: DHCPv4 & DHCPv6 · **Priority**: P1

## What it abuses

A DHCP server hands out addresses from a finite pool, and it hands them to whoever asks. DHCPv4 has no client authentication: the only identity a client presents is its MAC address and a transaction ID, both of which the client chooses.

## Protocols involved

- **DHCPv4** (RFC 2131, options in RFC 2132). The client broadcasts DISCOVER, the server answers with OFFER, the client confirms with REQUEST, and the server finishes with ACK.
- **Ethernet broadcast**: DHCP discovery is sent to `ff:ff:ff:ff:ff:ff`, so every host on the segment hears it.

## Goal

Empty the pool. If every address is leased to a fake client, a legitimate device that connects afterwards gets no address and no network. The attacker can then offer its own DHCP server, which is the next step in a classic man-in-the-middle, or simply deny service.

## How it works

1. Pick a random client MAC and a random transaction ID.
2. Send DISCOVER from that MAC.
3. When the server's OFFER arrives, send REQUEST for the offered address. Completing the handshake is what makes the server commit the lease.
4. Repeat with a new MAC until the pool is empty.

## What an auditor checks

- How large the pool is, and how fast it fills under a burst of fake clients.
- Whether a legitimate client still gets an address once the pool is full.
- Whether the switch limits how many DHCP messages an untrusted port may send.
- Whether the server limits leases per MAC or per relay agent.

## Defenses

- **DHCP snooping**: only trusted ports may send server messages, and untrusted ports get a rate limit for DHCP requests.
- **Port security**: a maximum number of MAC addresses per port stops one port from creating many clients.
- **Server-side limits**: leases per MAC or per relay agent, and alerts when the pool is nearly full.

## Related

[MAC flooding](../mac-address-cam-table/mac-flooding.md) also fills a table with fake identities, but in the switch instead of the DHCP server.
