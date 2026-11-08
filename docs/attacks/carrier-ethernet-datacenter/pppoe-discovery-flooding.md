# PPPoE Discovery Flooding

**Family**: Carrier Ethernet & Data Center · **Priority**: P2

## What it abuses

PPPoE sets up sessions with a discovery phase: the client broadcasts a PADI, and an access concentrator answers with a PADO. The concentrator allocates session state for each client that completes the phase, so a flood of discovery frames consumes its session pool.

## Protocols involved

- PPPoE Discovery (RFC 2516, EtherType 0x8863)
- PPP (RFC 1661)

## Goal

Use up the concentrator's session pool, so that legitimate clients cannot connect.

## How it works

The attacker sends PADI frames from many random MAC addresses. The concentrator answers each one and allocates resources for the sessions it offers. Legitimate clients then find no free session, which is the PPPoE equivalent of DHCP starvation.

## What an auditor checks

- Measure the session pool and the rate at which it fills.
- Check whether a legitimate client can connect after the pool is full.
- Check the per-port and per-MAC limits.

## Defenses

- Limits on sessions per port and per MAC.
- Rate limits for discovery frames.
- Monitoring of session pool use.

## Implementation status

- Module: `src/macabre/attacks/pppoe_discovery_flooding.py` (sends PADI frames from random or fixed client MACs, with no PADR).
- GUI panel: "PPPoE Discovery Flooding".
- Status: 🔨 Implemented. The lab validates that the concentrator answers each PADI in a flood with a PADO, and that a legitimate client still gets a PADO afterwards. It does not validate session pool exhaustion: that needs PPP sessions that stay open (no `/dev/ppp` and no pppd in the lab). A PADR without the concentrator's cookie gets no PADS, so the module does not send PADRs.

## Lab validation

`scripts/lab/pppoe_discovery_flooding_lab.sh` runs `pppoe-server` on a Linux bridge with an attacker and a client. Baseline: one probe gets one PADO. Flood: 200 of 200 PADI frames are answered with a PADO. After the flood, the probe still gets a PADO.

## Related

The other techniques in this family are listed in the [family index](README.md).
