# PTP Grandmaster Impersonation

**Family**: Industrial & Specialized L2 · **Priority**: P3

## What it abuses

PTP chooses its time source with the Best Master Clock Algorithm (BMCA), which compares the announced clock quality, priority and identity. A device that announces a better clock wins the election and becomes the grandmaster that the others follow.

## Protocols involved

- IEEE 1588 (PTP, BMCA)
- IEEE 802.1AS (gPTP)

## Goal

Become the time source of the whole domain, by announcing better clock values.

## How it works

The attacker sends Announce messages with a better clock class, accuracy or priority. The clocks in the domain run the BMCA and select the attacker as grandmaster. Every client then synchronizes to the attacker's time.

## What an auditor checks

- Identify the grandmaster and its announced values.
- Test whether a better Announce from an access port wins the election.
- Check whether grandmaster changes are logged.

## Defenses

- Fixed grandmaster priorities on trusted devices.
- Announce filters on access ports.
- Monitoring of grandmaster changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
