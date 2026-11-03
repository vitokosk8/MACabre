# Labs

The labs are MACabre's development test harness. Every attack has a lab script under `scripts/lab/` that builds a small test network on one Linux machine, runs the attack inside it, and reports what the switch and the hosts did. The labs exist so that each attack can be checked the same way, every time.

The labs are not how MACabre runs. The tool sends frames on the physical interface you choose, and the lab harness is only a way to test without a real switch. Nothing in a lab touches your real network interfaces, and the script removes everything it created when it ends.

## Requirements

- Linux with root access (`sudo`).
- `iproute2` (`ip`, `bridge`) and `ping`. The cloning lab also needs `nft` (nftables), and the DHCP lab needs `dnsmasq`.
- The project environment in `.venv`, or another interpreter set with `PYTHON=/path/to/python`.

## The labs

| Attack | Script | What it shows |
| --- | --- | --- |
| [DHCP starvation](attacks/dhcpv4-dhcpv6/dhcp-starvation.md) | `dhcp_starvation_lab.sh` | Leases granted to the attacker, and whether a legitimate client still gets an address |
| [MAC flooding](attacks/mac-address-cam-table/mac-flooding.md) | `mac_flooding_lab.sh` | Addresses the switch learns, and flooded frames received by a victim port |
| [MAC flapping](attacks/mac-address-cam-table/mac-flapping.md) | `mac_flapping_lab.sh` | How many times the switch moves one MAC between two ports |
| [MAC address spoofing](attacks/mac-address-cam-table/mac-address-spoofing.md) | `mac_spoofing_lab.sh` | The switch port of the target MAC before and after, and who receives its frames |
| [MAC cloning](attacks/mac-address-cam-table/mac-cloning.md) | `mac_cloning_lab.sh` | Frames dropped by a port that admits one MAC, then delivered after cloning |
| [ARP spoofing](attacks/arp/arp-spoofing.md) | `arp_spoofing_lab.sh` | The victim's ARP cache for the gateway, before and after |
| [ARP cache poisoning](attacks/arp/arp-cache-poisoning.md) | `arp_poisoning_lab.sh` | Both ARP caches, of the victim and of the gateway, before and after |
| [Gratuitous ARP spoofing](attacks/arp/gratuitous-arp-spoofing.md) | `gratuitous_arp_lab.sh` | Two victims' ARP caches changed by one broadcast announcement |
| [ARP request flooding](attacks/arp/arp-request-flooding.md) | `arp_request_flooding_lab.sh` | Flooded requests received by the victim, and the gateway's neighbor table growth |
| [ARP reply flooding](attacks/arp/arp-reply-flooding.md) | `arp_reply_flooding_lab.sh` | Replies received by the victim, and whether its neighbor table changes |
| [ARP-based gateway impersonation](attacks/arp/arp-based-gateway-impersonation.md) | `arp_gateway_impersonation_lab.sh` | Both victims' cached MAC for the gateway, before and after, and the attacker's forwarding setting |
| [Switch spoofing (DTP)](attacks/vlan-802-1q/switch-spoofing-dtp-spoofing.md) | `switch_spoofing_lab.sh` | DTP frames seen on the monitor port, and whether they are well formed. The trunk decision needs a real switch |
| [DTP negotiation abuse](attacks/discovery-management/dtp-negotiation-abuse.md) | `dtp_audit_lab.sh` | Trunk and access statuses advertised by a simulated port, and whether the audit's verdict follows the simulated mode. The status values and a real switch's decision are not tested |
| [Static MAC impersonation](attacks/mac-address-cam-table/static-mac-impersonation.md) | `static_mac_impersonation_lab.sh` | Whether frames claiming a statically registered MAC from another port move its static entry, and where unicast traffic for that MAC is delivered. Linux bridge only; real switches are not tested |
| [Port security exhaustion](attacks/mac-address-cam-table/port-security-exhaustion.md) | `port_security_exhaustion_lab.sh` | Addresses the switch learns on the attacker's port from new source MACs, and whether the legitimate host's entry is kept. Linux bridge has no per-port limit, so violation behavior is not tested |
| [MAC move / mobility abuse](attacks/mac-address-cam-table/mac-move-mobility-abuse.md) | `mac_move_lab.sh` | Whether one frame claiming a learned host's MAC from another port moves its dynamic entry, and where unicast traffic for it goes. Linux bridge only; move limits and allowed ports are not tested |
| [VLAN hopping](attacks/vlan-802-1q/vlan-hopping.md) | `vlan_hopping_lab.sh` | Tagged probes for VLAN 20 reaching the monitor, before and after the port carries that VLAN (the trunk outcome is simulated) |
| [Double-tagging](attacks/vlan-802-1q/double-tagging.md) | `double_tagging_lab.sh` | Frames with both tags reaching the monitor, before and after the port passes tagged frames (the switch's tag removal is not tested) |
| [Native VLAN abuse](attacks/vlan-802-1q/native-vlan-abuse.md) | `native_vlan_lab.sh` | Untagged probes reaching the monitor. The mismatch between trunk ends needs two real switches |
| [BPDU spoofing](attacks/spanning-tree/bpdu-spoofing.md) | `bpdu_spoofing_lab.sh` | Which switch port is the root port, before, during and after injected BPDUs, and when the switch returns to the legitimate root (uses the Linux kernel's Spanning Tree) |
| [Root bridge takeover](attacks/spanning-tree/root-bridge-takeover.md) | `root_bridge_takeover_lab.sh` | Which switch port is the root port while the attacker keeps its root claim refreshed, and when the switch returns to the legitimate root (uses the Linux kernel's Spanning Tree) |
| [Root bridge impersonation](attacks/spanning-tree/root-bridge-impersonation.md) | `root_bridge_impersonation_lab.sh` | Which switch port leads to the root while an impostor sends the real root's ID, and when the switch returns to the real root (uses the Linux kernel's Spanning Tree) |
| [Topology change flooding](attacks/spanning-tree/topology-change-flooding.md) | `topology_change_flooding_lab.sh` | Whether the monitor's MAC is flushed from the switch's table with and without the TC flag, against a control run. This kernel does not flush on the flag, so the effect needs a real switch |
| [TCN spoofing](attacks/spanning-tree/tcn-spoofing.md) | `tcn_spoofing_lab.sh` | Whether the switch acknowledges the TCNs, detects a topology change, and flushes a learned MAC (on this kernel: acknowledged and detected, no flush) |
| [BPDU flooding](attacks/spanning-tree/bpdu-flooding.md) | `bpdu_flooding_lab.sh` | Frames received by the switch at the requested rate, and whether the topology holds. The control-plane load and the delay to real updates are not measured |
| [Rogue DHCP server](attacks/dhcpv4-dhcpv6/rogue-dhcp-server.md) | `rogue_dhcp_server_lab.sh` | Which server's offer the client takes first, with the legitimate server running and stopped, and whether the rogue's ACK is accepted |
| [DHCP spoofing](attacks/dhcpv4-dhcpv6/dhcp-spoofing.md) | `dhcp_spoofing_lab.sh` | Whether a client accepts an offer and an ACK in the legitimate server's name, with the attacker's gateway, with the server running and stopped |
| [DHCP offer flooding](attacks/dhcpv4-dhcpv6/dhcp-offer-flooding.md) | `dhcp_offer_flooding_lab.sh` | Offers the client receives per round, how many come from the flood, and whether the client's first offer comes from an invented server, with the legitimate server running and stopped |
| [DHCP discover flooding](attacks/dhcpv4-dhcpv6/dhcp-discover-flooding.md) | `dhcp_discover_flooding_lab.sh` | DISCOVERs the server logs against the number sent, and whether a probe still gets an offer during the flood. No denial of service was seen at 2000 per second. CPU use is not measured |
| [DHCP NAK injection](attacks/dhcpv4-dhcpv6/dhcp-nak-injection.md) | `dhcp_nak_injection_lab.sh` | Whether a client's lease renewal is refused with a NAK in the server's name, with the legitimate server running and stopped, and whether the NAK wins the race against the real ACK |
| [CDP spoofing](attacks/discovery-management/cdp-spoofing.md) | `cdp_spoofing_lab.sh` | Whether a CDP receiver stores a forged neighbor with the advertised device, port, address and native VLAN, and whether it stores nothing once CDP is disabled on it |
| [CDP flooding](attacks/discovery-management/cdp-flooding.md) | `cdp_flooding_lab.sh` | Neighbor entries the receiver stores for a flood of random devices, whether an existing neighbor survives it, and whether a neighbor that appears after the flood is stored. The receiver is lldpd, so its table size is not a switch's; CPU use is not measured |
| [LLDP spoofing](attacks/discovery-management/lldp-spoofing.md) | `lldp_spoofing_lab.sh` | Whether an LLDP receiver stores a forged neighbor with the advertised system name, port and management address, and whether it stores nothing once LLDP receive is disabled on the port |
| [LLDP flooding](attacks/discovery-management/lldp-flooding.md) | `lldp_flooding_lab.sh` | Neighbor entries the receiver stores for a flood of random chassis, whether a legitimate neighbor is evicted, and whether a neighbor that appears after the flood is stored. The receiver is lldpd, so its table size is not a switch's; CPU use is not measured |
| [MNDP spoofing](attacks/discovery-management/mndp-spoofing.md) | `mndp_spoofing_lab.sh` | Whether a host on the segment hears the forged announcement and decodes it to the chosen identity, version and address. A RouterOS neighbor list is not available on Linux, and the field layout is not yet checked against a RouterOS capture |
| [MNDP flooding](attacks/discovery-management/mndp-flooding.md) | `mndp_flooding_lab.sh` | Announcements a host on the segment decodes from a flood at the requested rate, and the distinct routers they name. A RouterOS neighbor list and CPU use are not measured |
| [Broadcast storm](attacks/l2-multicast-broadcast/broadcast-storm.md) | `broadcast_storm_lab.sh` | Broadcasts the receiver gets from a flood on one link, whether STP stops a loop to one copy, and, with `LOOP_TEST=1`, how many copies one broadcast makes in a loop without STP |
| [Multicast flooding](attacks/l2-multicast-broadcast/multicast-flooding.md) | `multicast_flooding_lab.sh` | Frames a host that joined no group receives from a flood to random groups, and whether turning off flooding of unknown multicast on its port stops them |
| [VLAN tag injection](attacks/vlan-802-1q/vlan-tag-injection.md) | `vlan_tag_injection_lab.sh` | Injected-tag frames reaching the monitor, and whether their VLAN ID and priority are unchanged (the switch's decision is simulated) |
| [MAB bypass / MAC spoofing](attacks/802-1x-eapol-nac/mab-bypass-mac-spoofing.md) | `mab_bypass_lab.sh` | Whether a port with a MAC allow list replies to a probe sent with the attacker's own MAC and with the allowed MAC, and whether the attacker's MAC is restored. Models an allow list only, not RADIUS or 802.1X |

Run any of them with `sudo`, from the project root:

```bash
sudo scripts/lab/mac_flooding_lab.sh
sudo FRAMES=2000 scripts/lab/mac_flooding_lab.sh
```

Most labs accept a size parameter (`FRAMES`, `SPOOF_FRAMES`, `REPLY_SECONDS`, `ANNOUNCEMENTS`) to change how much traffic they send.

## Limits of the labs

- The switch is a Linux bridge, which is software. It has no CAM table size limit, no port security and no vendor behavior. The labs test the logic of each attack and the way a learning switch reacts to it, not the behavior of a specific device.
- Port security in the cloning lab is emulated with an nftables rule on the bridge.
- The DHCP lab uses `dnsmasq --no-ping`, which skips the ARP check before each offer, so the lab runs faster. That setting belongs to the lab, not to the attack.

To test on real hardware, use a dedicated Ethernet adapter connected to a switch you control. Wi-Fi access points drop frames whose MAC address is not associated, so Wi-Fi is not suitable for these tests.
