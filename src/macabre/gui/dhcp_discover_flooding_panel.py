"""Panel for the DHCP discover flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.dhcp_discover_flooding import MAX_RATE, DiscoverFloodConfig, DiscoverFloodStats, run_discover_flooding
from macabre.gui.base_panel import AttackPanel


class DhcpDiscoverFloodingPanel(AttackPanel):
    title = "DHCP Discover Flooding"
    description = (
        "Sends DHCPDISCOVER messages at a set rate from random client MACs, with no requests. The server must "
        "process each one, which can slow it and fill its logs. The lab showed no denial of service at 2000 "
        "per second. Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(200)
        self.rate_spin.setSuffix(" DISCOVER/s")
        self.rate_spin.setToolTip("DISCOVERs per second. The interval setting does not apply to this attack.")
        form.addRow("Rate:", self.rate_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.rate_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> DiscoverFloodConfig:
        del interval  # the rate sets the timing for this attack
        return DiscoverFloodConfig(iface=iface, rate=float(self.rate_spin.value()), count=count, dry_run=dry_run)

    def _run_attack(
        self,
        config: DiscoverFloodConfig,
        stop_event: threading.Event,
        on_progress: Callable[[DiscoverFloodStats], None],
    ) -> DiscoverFloodStats:
        return run_discover_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: DiscoverFloodStats) -> str:
        return stats.status or f"DISCOVERs sent: {stats.frames}"
