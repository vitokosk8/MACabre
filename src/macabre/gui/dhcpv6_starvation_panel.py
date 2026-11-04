"""Panel for the DHCPv6 starvation attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QDoubleSpinBox, QFormLayout, QSpinBox

from macabre.attacks.dhcpv6_starvation import (
    Dhcpv6StarvationConfig,
    Dhcpv6StarvationStats,
    run_dhcpv6_starvation,
)
from macabre.gui.base_panel import AttackPanel


class Dhcpv6StarvationPanel(AttackPanel):
    title = "DHCPv6 Starvation"
    description = (
        "Sends DHCPv6 SOLICIT messages with random client identities and completes them, so the server's "
        "IPv6 pool fills. Use only with authorization."
    )
    default_interval = 0.05
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.count_spin = QSpinBox()
        self.count_spin.setRange(0, 1_000_000)
        self.count_spin.setSpecialValueText("until stopped")
        self.count_spin.setValue(0)
        form.addRow("Solicits:", self.count_spin)

        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(0.0, 10.0)
        self.interval_spin.setDecimals(3)
        self.interval_spin.setSingleStep(0.01)
        self.interval_spin.setValue(0.05)
        self.interval_spin.setSuffix(" s")
        form.addRow("Interval:", self.interval_spin)

        self.request_check = QCheckBox("Complete each exchange with a REQUEST (creates the binding)")
        self.request_check.setChecked(True)
        form.addRow("", self.request_check)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.count_spin, self.interval_spin, self.request_check):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> Dhcpv6StarvationConfig:
        del count, interval  # taken from this panel's own controls
        return Dhcpv6StarvationConfig(
            iface=iface,
            count=self.count_spin.value(),
            interval=self.interval_spin.value(),
            request=self.request_check.isChecked(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: Dhcpv6StarvationConfig,
        stop_event: threading.Event,
        on_progress: Callable[[Dhcpv6StarvationStats], None],
    ) -> Dhcpv6StarvationStats:
        return run_dhcpv6_starvation(config, stop_event, on_progress)

    def _format_status(self, stats: Dhcpv6StarvationStats) -> str:
        return stats.status or (
            f"Solicits: {stats.solicits}, advertises: {stats.advertises}, requests: {stats.requests}"
        )
