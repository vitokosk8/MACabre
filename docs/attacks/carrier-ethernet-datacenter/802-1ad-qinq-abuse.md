# 802.1ad QinQ Abuse

**Family**: Carrier Ethernet & Data Center · **Priority**: P2

## What it abuses

IEEE 802.1ad (provider bridges) adds a service tag (S-tag) outside the customer tag (C-tag). Provider bridges forward by the S-tag and leave the C-tag untouched. Provider edges that copy or trust the C-tag can be made to send customer traffic into another service.

## Protocols involved

- IEEE 802.1ad (provider bridges, S-tag and C-tag)
- IEEE 802.1Q

## Goal

Send customer traffic into another service, by controlling the tags that the provider edge trusts.

## How it works

The attacker sends customer frames with a C-tag that matches another customer's service, or with a chosen S-tag if the provider edge does not overwrite it. The provider bridge forwards the frame by the tags it sees, and the frame reaches the other customer's service or another network.

## What an auditor checks

- Check how the provider edge sets the S-tag on ingress.
- Test customer frames with foreign C-tags.
- Verify that customers cannot see each other's services.

## Defenses

- Provider edge that sets the S-tag itself and drops customer tags it does not expect.
- Separate C-tag ranges per customer.
- Monitoring of service tag mismatches.

## Related

The other techniques in this family are listed in the [family index](README.md).
