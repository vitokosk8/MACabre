"""Panel for the LLDP spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.lldp_spoofing import DEFAULT_INTERVAL, LldpSpoofingConfig, LldpSpoofingStats, run_lldp_spoofing
from macabre.gui.base_panel import AttackPanel


class LldpSpoofingPanel(AttackPanel):
    title = "LLDP Spoofing"
    description = (
        "Advertises a forged network device over LLDP, with the system name, port and management address you "
        "choose, to the neighbors on the segment. Receivers that keep LLDP neighbors store it. Use only with "
        "authorization."
    )
    default_interval = DEFAULT_INTERVAL

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.name_edit = QLineEdit("MACabre-SW")
        form.addRow("System name:", self.name_edit)

        self.port_edit = QLineEdit("GigabitEthernet0/1")
        form.addRow("Port ID:", self.port_edit)

        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("Management address (optional), e.g. 10.0.0.9")
        form.addRow("Address:", self.address_edit)

        self.chassis_edit = QLineEdit()
        self.chassis_edit.setPlaceholderText("Chassis MAC (optional; empty = this interface)")
        form.addRow("Chassis MAC:", self.chassis_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.name_edit, self.port_edit, self.address_edit, self.chassis_edit):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> LldpSpoofingConfig:
        return LldpSpoofingConfig(
            iface=iface,
            system_name=self.name_edit.text().strip(),
            port_id=self.port_edit.text().strip(),
            address=self.address_edit.text().strip(),
            chassis_mac=self.chassis_edit.text().strip(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: LldpSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[LldpSpoofingStats], None],
    ) -> LldpSpoofingStats:
        return run_lldp_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: LldpSpoofingStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
