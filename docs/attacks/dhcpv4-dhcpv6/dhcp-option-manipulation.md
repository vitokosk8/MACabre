# DHCP Option Manipulation

**Family**: DHCPv4 & DHCPv6 · **Priority**: P2

## What it abuses

DHCP options set the default gateway, DNS servers, domain, NTP servers and other settings. A client accepts the options from the first valid server, so changing an option changes how the client routes and resolves names.

## Protocols involved

- DHCPv4 options (RFC 2132)

## Goal

Change the gateway, the DNS servers or other settings that clients receive, so that their traffic goes through the attacker.

## How it works

The attacker answers a request with a server reply that sets a different DNS server or gateway. The client applies those values, and its name resolution or routing passes through the attacker. The change is silent, because the client believes it received a normal configuration.

## What an auditor checks

- List the options each client receives, and compare them with the design.
- Test whether a changed option is applied.
- Check whether the client logs the server it used.

## Defenses

- DHCP snooping with trusted server ports.
- Monitoring of configuration changes on clients.
- Encrypted DNS and verified time sources where possible.

## Implementation status

- Module: `src/macabre/attacks/dhcp_option_manipulation.py`. It reuses the spoofed reply of DHCP Spoofing and adds the selected options: domain (15), NTP server (42), search domains (119), static routes (121) and WPAD (252).
- GUI panel: "DHCP Option Manipulation".
- Status: 🔨 Implemented. The lab validates that a client receives the WPAD option from the attacker alone; the client's handling of the option is not tested.

## Lab validation

`scripts/lab/dhcp_option_manipulation_lab.sh` runs dnsmasq as the legitimate server. Alone, the server sends no WPAD option. With the legitimate server stopped, the attacker's reply carries the WPAD URL, and the client receives it.

## Related

The other techniques in this family are listed in the [family index](README.md).
