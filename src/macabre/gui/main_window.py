"""Main window: attack menu on the left, attack panel on the right.

The menu is generated from the attack catalog (macabre.catalog), so families
and techniques always match docs/attack-catalog.md.
"""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStackedWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from macabre import __version__
from macabre.catalog import FAMILIES
from macabre.gui.arp_gateway_impersonation_panel import ArpGatewayImpersonationPanel
from macabre.gui.bpdu_spoofing_panel import BpduSpoofingPanel
from macabre.gui.root_bridge_takeover_panel import RootBridgeTakeoverPanel
from macabre.gui.root_bridge_impersonation_panel import RootBridgeImpersonationPanel
from macabre.gui.topology_change_flooding_panel import TopologyChangeFloodingPanel
from macabre.gui.tcn_spoofing_panel import TcnSpoofingPanel
from macabre.gui.bpdu_flooding_panel import BpduFloodingPanel
from macabre.gui.rogue_dhcp_server_panel import RogueDhcpServerPanel
from macabre.gui.dhcp_spoofing_panel import DhcpSpoofingPanel
from macabre.gui.dhcp_offer_flooding_panel import DhcpOfferFloodingPanel
from macabre.gui.dhcp_discover_flooding_panel import DhcpDiscoverFloodingPanel
from macabre.gui.dhcp_nak_injection_panel import DhcpNakInjectionPanel
from macabre.gui.cdp_spoofing_panel import CdpSpoofingPanel
from macabre.gui.cdp_flooding_panel import CdpFloodingPanel
from macabre.gui.lldp_spoofing_panel import LldpSpoofingPanel
from macabre.gui.lldp_flooding_panel import LldpFloodingPanel
from macabre.gui.mndp_spoofing_panel import MndpSpoofingPanel
from macabre.gui.mndp_flooding_panel import MndpFloodingPanel
from macabre.gui.broadcast_storm_panel import BroadcastStormPanel
from macabre.gui.multicast_flooding_panel import MulticastFloodingPanel
from macabre.gui.arp_reply_flooding_panel import ArpReplyFloodingPanel
from macabre.gui.switch_spoofing_panel import SwitchSpoofingPanel
from macabre.gui.double_tagging_panel import DoubleTaggingPanel
from macabre.gui.native_vlan_panel import NativeVlanPanel
from macabre.gui.vlan_tag_injection_panel import VlanTagInjectionPanel
from macabre.gui.vlan_hopping_panel import VlanHoppingPanel
from macabre.gui.arp_request_flooding_panel import ArpRequestFloodingPanel
from macabre.gui.arp_poisoning_panel import ArpPoisoningPanel
from macabre.gui.arp_spoofing_panel import ArpSpoofingPanel
from macabre.gui.gratuitous_arp_panel import GratuitousArpPanel
from macabre.gui.dhcp_panel import DhcpStarvationPanel
from macabre.gui.icons import app_icon
from macabre.gui.mac_flapping_panel import MacFlappingPanel
from macabre.gui.mac_flooding_panel import MacFloodingPanel
from macabre.gui.mac_cloning_panel import MacCloningPanel
from macabre.gui.mac_spoofing_panel import MacSpoofingPanel
from macabre.gui.dtp_audit_panel import DtpAuditPanel
from macabre.gui.mab_bypass_panel import MabBypassPanel
from macabre.gui.arp_table_exhaustion_panel import ArpTableExhaustionPanel
from macabre.gui.proxy_arp_abuse_panel import ProxyArpAbusePanel
from macabre.gui.mac_move_panel import MacMovePanel
from macabre.gui.unknown_unicast_flooding_panel import UnknownUnicastFloodingPanel
from macabre.gui.port_security_exhaustion_panel import PortSecurityExhaustionPanel
from macabre.gui.static_mac_impersonation_panel import StaticMacImpersonationPanel
from macabre.gui.dhcp_release_spoofing_panel import DhcpReleaseSpoofingPanel
from macabre.gui.dhcp_option_manipulation_panel import DhcpOptionManipulationPanel
from macabre.gui.dhcp_relay_option82_panel import DhcpRelayOption82Panel
from macabre.gui.rogue_dhcpv6_server_panel import RogueDhcpv6ServerPanel
from macabre.gui.dhcpv6_starvation_panel import Dhcpv6StarvationPanel
from macabre.gui.igmp_spoofing_panel import IgmpSpoofingPanel
from macabre.gui.igmp_leave_spoofing_panel import IgmpLeaveSpoofingPanel
from macabre.gui.lldp_med_policy_spoofing_panel import LldpMedPolicySpoofingPanel
from macabre.gui.bpdu_guard_trigger_abuse_panel import BpduGuardTriggerAbusePanel
from macabre.gui.unauthorized_mini_switch_panel import UnauthorizedMiniSwitchPanel
from macabre.gui.private_vlan_bypass_panel import PrivateVlanBypassPanel
from macabre.gui.pppoe_discovery_flooding_panel import PppoeDiscoveryFloodingPanel
from macabre.gui.rogue_pppoe_access_concentrator_panel import RoguePppoeAccessConcentratorPanel
from macabre.gui.eapol_start_flooding_panel import EapolStartFloodingPanel
from macabre.gui.eapol_logoff_spoofing_panel import EapolLogoffSpoofingPanel
from macabre.gui.qinq_stacking_panel import QinQStackingPanel

# Panels for implemented techniques, keyed by technique name from the catalog.
PANELS = {
    "DHCP Starvation": DhcpStarvationPanel,
    "MAC Flooding / CAM Overflow": MacFloodingPanel,
    "MAC Flapping": MacFlappingPanel,
    "MAC Address Spoofing": MacSpoofingPanel,
    "MAC Cloning": MacCloningPanel,
    "ARP Spoofing": ArpSpoofingPanel,
    "ARP Cache Poisoning": ArpPoisoningPanel,
    "Gratuitous ARP Spoofing": GratuitousArpPanel,
    "ARP Request Flooding": ArpRequestFloodingPanel,
    "ARP Reply Flooding": ArpReplyFloodingPanel,
    "ARP-Based Gateway Impersonation": ArpGatewayImpersonationPanel,
    "Switch Spoofing / DTP Spoofing": SwitchSpoofingPanel,
    "VLAN Hopping": VlanHoppingPanel,
    "Double-Tagging": DoubleTaggingPanel,
    "Native VLAN Abuse": NativeVlanPanel,
    "VLAN Tag Injection": VlanTagInjectionPanel,
    "BPDU Spoofing": BpduSpoofingPanel,
    "DTP Negotiation Abuse": DtpAuditPanel,
    "MAB Bypass / MAC Spoofing": MabBypassPanel,
    "Static MAC Impersonation": StaticMacImpersonationPanel,
    "Port Security Exhaustion": PortSecurityExhaustionPanel,
    "MAC Move / Mobility Abuse": MacMovePanel,
    "Unknown Unicast Flooding": UnknownUnicastFloodingPanel,
    "ARP Table Exhaustion": ArpTableExhaustionPanel,
    "Proxy ARP Abuse": ProxyArpAbusePanel,
    "QinQ / VLAN Stacking Abuse": QinQStackingPanel,
    "DHCP Release Spoofing": DhcpReleaseSpoofingPanel,
    "DHCP Option Manipulation": DhcpOptionManipulationPanel,
    "DHCP Relay / Option 82 Abuse": DhcpRelayOption82Panel,
    "Rogue DHCPv6 Server": RogueDhcpv6ServerPanel,
    "DHCPv6 Starvation": Dhcpv6StarvationPanel,
    "IGMP Spoofing": IgmpSpoofingPanel,
    "IGMP Leave Spoofing": IgmpLeaveSpoofingPanel,
    "LLDP-MED Policy Spoofing": LldpMedPolicySpoofingPanel,
    "BPDU Guard Trigger Abuse": BpduGuardTriggerAbusePanel,
    "Unauthorized Mini-Switch / Hub": UnauthorizedMiniSwitchPanel,
    "Private VLAN Isolation Bypass": PrivateVlanBypassPanel,
    "PPPoE Discovery Flooding": PppoeDiscoveryFloodingPanel,
    "Rogue PPPoE Access Concentrator": RoguePppoeAccessConcentratorPanel,
    "EAPOL Start Flooding": EapolStartFloodingPanel,
    "EAPOL Logoff Spoofing": EapolLogoffSpoofingPanel,
    "Root Bridge Takeover": RootBridgeTakeoverPanel,
    "Root Bridge Impersonation": RootBridgeImpersonationPanel,
    "Topology Change Flooding": TopologyChangeFloodingPanel,
    "TCN Spoofing": TcnSpoofingPanel,
    "BPDU Flooding": BpduFloodingPanel,
    "Rogue DHCP Server": RogueDhcpServerPanel,
    "DHCP Spoofing": DhcpSpoofingPanel,
    "DHCP Offer Flooding": DhcpOfferFloodingPanel,
    "DHCP Discover Flooding": DhcpDiscoverFloodingPanel,
    "DHCP NAK Injection": DhcpNakInjectionPanel,
    "CDP Spoofing": CdpSpoofingPanel,
    "CDP Flooding": CdpFloodingPanel,
    "LLDP Spoofing": LldpSpoofingPanel,
    "LLDP Flooding": LldpFloodingPanel,
    "MNDP Spoofing": MndpSpoofingPanel,
    "MNDP Flooding": MndpFloodingPanel,
    "Broadcast Storm": BroadcastStormPanel,
    "Multicast Flooding": MulticastFloodingPanel,
}


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"MACabre {__version__}")
        self.setWindowIcon(app_icon())
        self.resize(960, 600)

        self._pages: dict[str, int] = {}
        self._stack = QStackedWidget()
        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.currentItemChanged.connect(self._on_selection_changed)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._tree)
        splitter.addWidget(self._stack)
        splitter.setStretchFactor(1, 1)
        self.setCentralWidget(splitter)

        self._build_tree()
        self._build_menus()
        self.statusBar().showMessage(self._privilege_status())

    # --- structure --------------------------------------------------------

    def _build_tree(self) -> None:
        self._stack.addWidget(QLabel("Select an attack from the menu on the left."))

        for family in FAMILIES:
            family_item = QTreeWidgetItem([family.name])
            self._tree.addTopLevelItem(family_item)
            for technique in family.techniques:
                item = QTreeWidgetItem([technique.name])
                item.setData(0, Qt.ItemDataRole.UserRole, technique.name)
                family_item.addChild(item)
                if technique.name in PANELS:
                    self._pages[technique.name] = self._stack.addWidget(
                        self._create_page(technique.name)
                    )
                else:
                    item.setDisabled(True)
                    item.setText(0, f"{technique.name} (planned)")

        self._tree.expandAll()

    def _create_page(self, name: str) -> QWidget:
        return PANELS[name]()

    def _build_menus(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        quit_action = file_menu.addAction("&Quit")
        quit_action.triggered.connect(self.close)

        help_menu = self.menuBar().addMenu("&Help")
        about_action = help_menu.addAction("&About")
        about_action.triggered.connect(self._show_about)

    # --- events -----------------------------------------------------------

    def _on_selection_changed(self, current: QTreeWidgetItem | None, _previous) -> None:
        if current is None:
            return
        name = current.data(0, Qt.ItemDataRole.UserRole)
        if name in self._pages:
            self._stack.setCurrentIndex(self._pages[name])

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About MACabre",
            f"MACabre {__version__}\n\n"
            "Layer 2 network auditing suite.\n"
            "Use only with explicit authorization.\n\n"
            "Author: vitokosk8 Victor Bolaños Guerra\n"
            "Original repository: https://github.com/vitokosk8/MACabre\n"
            "Inspired by Yersinia: https://github.com/tomac/yersinia\n\n"
            "Licensed under the Apache License 2.0. Copyright 2026.",
        )

    # --- helpers ----------------------------------------------------------

    @staticmethod
    def _privilege_status() -> str:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return "Privileges: root (frame sending available)."
        return "No root privileges: frame sending will fail. Run with sudo."
