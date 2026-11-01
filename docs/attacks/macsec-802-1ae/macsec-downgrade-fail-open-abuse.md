# MACsec Downgrade / Fail-Open Abuse

**Family**: MACsec / IEEE 802.1AE · **Priority**: P3

## What it abuses

MACsec can be required on a port, or it can be optional. When MKA fails, a port configured to fail open passes traffic in clear, so an attacker who breaks the key agreement can make the link unprotected without anyone noticing.

## Protocols involved

- IEEE 802.1AE (MACsec)
- IEEE 802.1X-2010 (MKA)

## Goal

Make a link carry clear traffic when MACsec fails, so that the traffic can be read.

## How it works

The attacker disrupts the MKA exchange. A port that accepts clear traffic when MACsec is not established carries the frames unencrypted. The downgrade is silent unless the switch logs it, so the audit checks the policy and the log.

## What an auditor checks

- Check the policy for a failed MKA on each port.
- Test the port behavior when MKA is disrupted.
- Check whether a fallback is logged and alerted.

## Defenses

- Strict mode that drops traffic when MACsec is not established.
- Alerts on any port that carries clear traffic.
- Monitoring of MACsec state.

## Related

The other techniques in this family are listed in the [family index](README.md).
