"""Panel for the MAB bypass (MAC-based authentication) audit."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit

from macabre.attacks.mab_bypass import MabBypassConfig, MabBypassStats, run_mab_bypass
from macabre.gui.base_panel import AttackPanel


class MabBypassPanel(AttackPanel):
    title = "MAB bypass (MAC spoofing)"
    description = (
        "Clones the MAC address of a device allowed by MAC-based authentication, probes the gateway "
        "once with it, and restores this interface's own MAC. Reports whether the port accepted the "
        "allowed identity. Changes this interface's MAC while it runs. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Allowed device MAC, e.g. 02:00:00:00:00:50")
        form.addRow("Allowed MAC:", self.target_edit)
        self.gateway_edit = QLineEdit()
        self.gateway_edit.setPlaceholderText("IPv4 address of a host on the VLAN, e.g. 10.99.0.1")
        form.addRow("Gateway:", self.gateway_edit)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.target_edit.setEnabled(enabled)
        self.gateway_edit.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MabBypassConfig:
        del count, interval  # one probe per run
        return MabBypassConfig(
            iface=iface,
            target_mac=self.target_edit.text().strip(),
            gateway_ip=self.gateway_edit.text().strip(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: MabBypassConfig,
        stop_event: threading.Event,
        on_progress: Callable[[MabBypassStats], None],
    ) -> MabBypassStats:
        return run_mab_bypass(config, stop_event, on_progress)

    def _format_status(self, stats: MabBypassStats) -> str:
        return stats.status or "MAB probe not finished"
