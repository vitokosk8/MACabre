# VXLAN VNI / VTEP Spoofing

**Family**: Carrier Ethernet & Data Center · **Priority**: P3

## What it abuses

VXLAN carries Ethernet frames over IP. Each tunnel endpoint (VTEP) maps a VXLAN network identifier (VNI) to a bridge domain. A forged VTEP or a frame with another VNI can deliver traffic to a different tenant, because the VNI is what separates the tenants.

## Protocols involved

- VXLAN (RFC 7348)
- IP and UDP

## Goal

Reach another tenant's network, by sending frames with its VNI or from a false endpoint.

## How it works

The attacker sends VXLAN packets with a VNI used by another tenant, or from an address that looks like a VTEP. A VTEP that does not check the source or the VNI bridges the frame into that tenant's domain.

## What an auditor checks

- Check the VNI mapping on each VTEP.
- Test whether packets from an unknown VTEP are accepted.
- Verify that tenants cannot reach each other's VNIs.

## Defenses

- Source checks on VTEP addresses.
- VNI filters on the underlay.
- Monitoring of VNI and VTEP changes.

## Related

The other techniques in this family are listed in the [family index](README.md).
