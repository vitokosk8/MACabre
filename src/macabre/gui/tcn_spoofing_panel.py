"""Panel for the TCN spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout

from macabre.attacks.tcn_spoofing import TcnSpoofingConfig, TcnSpoofingStats, run_tcn_spoofing
from macabre.gui.base_panel import AttackPanel


class TcnSpoofingPanel(AttackPanel):
    title = "TCN Spoofing"
    description = (
        "Sends topology change notifications (TCN BPDUs) from a designated switch port. A switch that accepts "
        "them acknowledges them and signals a topology change, which can flush its MAC table. Use only with "
        "authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        del form  # no extra fields: a TCN has no configurable content

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        del enabled

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> TcnSpoofingConfig:
        return TcnSpoofingConfig(iface=iface, count=count, interval=interval, dry_run=dry_run)

    def _run_attack(
        self,
        config: TcnSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[TcnSpoofingStats], None],
    ) -> TcnSpoofingStats:
        return run_tcn_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: TcnSpoofingStats) -> str:
        return stats.status or f"TCNs sent: {stats.frames}"
