# Provider Ethernet OAM Abuse

**Family**: Carrier Ethernet & Data Center · **Priority**: P3

## What it abuses

Service-level OAM for provider Ethernet (ITU-T Y.1731) tests the connectivity of a service between customer endpoints. Loopback and linktrace messages are used to find faults, and a forged message from a provider endpoint can alter the test results or trigger a false fault.

## Protocols involved

- ITU-T Y.1731 (service OAM)
- IEEE 802.1ag (CFM)

## Goal

Alter the results of service tests, or trigger false faults in the provider's tools.

## How it works

The attacker sends loopback or linktrace messages that carry a provider endpoint identifier. If the provider network accepts them from a customer port, the test results can be changed, or the provider's fault tools report a false path. The audit checks that these messages stay inside the provider network.

## What an auditor checks

- Test whether service OAM from a customer port is accepted.
- Check the identifiers of provider endpoints.
- Verify that OAM is filtered at the customer edge.

## Defenses

- Filter OAM at the customer edge.
- Authenticated and identified endpoints.
- Monitoring of fault reports.

## Related

The other techniques in this family are listed in the [family index](README.md).
