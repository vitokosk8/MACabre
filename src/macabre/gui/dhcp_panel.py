"""Panel for the DHCP starvation attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QFormLayout

from macabre.attacks.dhcp_starvation import (
    DhcpStarvationConfig,
    StarvationStats,
    run_starvation,
)
from macabre.gui.base_panel import AttackPanel


class DhcpStarvationPanel(AttackPanel):
    title = "DHCP starvation"
    description = (
        "Sends DHCPDISCOVER messages with random MAC addresses and completes the "
        "handshake, so the server's address pool is exhausted. Use only with authorization."
    )
    default_interval = 0.05

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.request_check = QCheckBox("Complete handshake (send REQUEST for each OFFER)")
        self.request_check.setChecked(True)
        form.addRow("", self.request_check)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.request_check.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> DhcpStarvationConfig:
        # request_check is created in _add_extra_controls, which the base class runs first.
        return DhcpStarvationConfig(
            iface=iface,
            count=count,
            interval=interval,
            request=self.request_check.isChecked(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: DhcpStarvationConfig,
        stop_event: threading.Event,
        on_progress: Callable[[StarvationStats], None],
    ) -> StarvationStats:
        return run_starvation(config, stop_event, on_progress)

    def _format_status(self, stats: StarvationStats) -> str:
        return f"DISCOVER: {stats.discovers}   OFFER: {stats.offers}   REQUEST: {stats.requests}"
