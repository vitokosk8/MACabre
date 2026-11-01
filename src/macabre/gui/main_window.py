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
    "Root Bridge Takeover": RootBridgeTakeoverPanel,
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
