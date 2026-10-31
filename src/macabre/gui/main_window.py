"""Main window: attack tree on the left, attack panel on the right."""

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
)

from macabre import __version__
from macabre.gui.dhcp_panel import DhcpStarvationPanel

# Menu structure: category > protocol > attack. Attacks without a panel are
# shown disabled until they are implemented.
ATTACK_TREE = {
    "Layer 2": {
        "DHCP": ["Starvation"],
        "LLDP": ["Exhaustion"],
        "CDP": ["Flooding"],
        "Spanning Tree": ["BPDU manipulation"],
    },
}

IMPLEMENTED = {("Layer 2", "DHCP", "Starvation")}


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"macabre {__version__}")
        self.resize(960, 600)

        self._pages: dict[tuple[str, ...], int] = {}
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

        for category, protocols in ATTACK_TREE.items():
            cat_item = QTreeWidgetItem([category])
            self._tree.addTopLevelItem(cat_item)
            for protocol, attacks in protocols.items():
                proto_item = QTreeWidgetItem([protocol])
                cat_item.addChild(proto_item)
                for attack in attacks:
                    key = (category, protocol, attack)
                    attack_item = QTreeWidgetItem([attack])
                    attack_item.setData(0, Qt.ItemDataRole.UserRole, key)
                    proto_item.addChild(attack_item)
                    if key in IMPLEMENTED:
                        page = self._create_page(key)
                        self._pages[key] = self._stack.addWidget(page)
                    else:
                        attack_item.setDisabled(True)
                        attack_item.setText(0, f"{attack} (coming soon)")

        self._tree.expandAll()

    def _create_page(self, key: tuple[str, ...]) -> QLabel | DhcpStarvationPanel:
        if key == ("Layer 2", "DHCP", "Starvation"):
            return DhcpStarvationPanel()
        return QLabel("Coming soon.")

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
        key = current.data(0, Qt.ItemDataRole.UserRole)
        if key in self._pages:
            self._stack.setCurrentIndex(self._pages[key])

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About macabre",
            f"macabre {__version__}\n\n"
            "Layer 2 network auditing suite.\n"
            "Use only with explicit authorization.",
        )

    # --- helpers ----------------------------------------------------------

    @staticmethod
    def _privilege_status() -> str:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return "Privileges: root (frame sending available)."
        return "No root privileges: frame sending will fail. Run with sudo."
