# DHCP Relay / Option 82 Abuse

**Family**: DHCPv4 & DHCPv6 · **Priority**: P2

## What it abuses

A relay agent forwards DHCP messages from clients on other subnets and can add Option 82, which identifies the port and circuit the client is on. Servers use Option 82 to choose addresses. A client that can insert or change Option 82 can choose the address pool it receives.

## Protocols involved

- DHCPv4 relay agent (RFC 3046, Option 82)
- DHCP options (RFC 2132)

## Goal

Choose the address pool a client receives, by forging the port identity in Option 82.

## How it works

The attacker sends a DISCOVER with a forged Option 82 that names a port or circuit the attacker is not on. The relay forwards it unchanged, and the server allocates from the pool for that port. The attacker can receive addresses meant for another part of the network.

## What an auditor checks

- Check whether the relay overwrites client-supplied Option 82 values.
- Test whether a forged Option 82 changes the pool.
- Check the server's pool selection rules.

## Defenses

- Relay agents that replace any client-supplied Option 82.
- Pool selection tied to the port identity the switch provides.
- DHCP snooping on access ports.

## Related

The other techniques in this family are listed in the [family index](README.md).
