"""Panel for the MNDP spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.mndp_spoofing import DEFAULT_INTERVAL, MndpSpoofingConfig, MndpSpoofingStats, run_mndp_spoofing
from macabre.gui.base_panel import AttackPanel


class MndpSpoofingPanel(AttackPanel):
    title = "MNDP Spoofing"
    description = (
        "Announces a forged MikroTik router over MikroTik Neighbor Discovery (UDP 5678), with the identity, "
        "interface and address you choose. RouterOS devices that hear it can list it as a neighbor. "
        "Use only with authorization."
    )
    default_interval = DEFAULT_INTERVAL

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.identity_edit = QLineEdit("MACabre-RTR")
        form.addRow("Identity:", self.identity_edit)

        self.version_edit = QLineEdit("7.16")
        form.addRow("Version:", self.version_edit)

        self.board_edit = QLineEdit("RB750Gr3")
        form.addRow("Board:", self.board_edit)

        self.interface_edit = QLineEdit("ether1")
        form.addRow("Interface name:", self.interface_edit)

        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("IPv4 address (optional), e.g. 10.0.0.9")
        form.addRow("Address:", self.address_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.identity_edit, self.version_edit, self.board_edit, self.interface_edit, self.address_edit):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MndpSpoofingConfig:
        return MndpSpoofingConfig(
            iface=iface,
            identity=self.identity_edit.text().strip(),
            version=self.version_edit.text().strip() or "7.16",
            board=self.board_edit.text().strip() or "RB750Gr3",
            interface_name=self.interface_edit.text().strip() or "ether1",
            address=self.address_edit.text().strip(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: MndpSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[MndpSpoofingStats], None],
    ) -> MndpSpoofingStats:
        return run_mndp_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: MndpSpoofingStats) -> str:
        return stats.status or f"Announcements sent: {stats.frames}"
