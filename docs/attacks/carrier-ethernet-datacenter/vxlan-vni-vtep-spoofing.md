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

## Implementation status

Implemented in MACabre as its own panel entry. The module sends VXLAN frames with the VNI, outer addresses and inner source MAC the operator gives. Validated on a Linux VXLAN device, with the VNI as the only accepting condition the lab checks. Real VTEPs are not tested.

## Lab validation

Lab: `scripts/lab/vxlan_vtep_spoofing_lab.sh` (Linux VXLAN device for VNI 42, learning on, in namespaces). Control: the legitimate VTEP's frame teaches the target that the victim MAC is behind 10.0.0.1. Attack: frames from 10.0.0.3 with the same inner MAC move it to 10.0.0.3. VNI check: a frame on VNI 43 teaches nothing, because the target has no device for that VNI. Exit 0 when all three hold. Vendor VTEPs are not tested.

## Related

The other techniques in this family are listed in the [family index](README.md).
