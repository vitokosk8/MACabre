"""Panel for the MAC flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from macabre.attacks.mac_flooding import (
    FloodingStats,
    MacFloodingConfig,
    run_flooding,
)
from macabre.gui.base_panel import AttackPanel


class MacFloodingPanel(AttackPanel):
    title = "MAC flooding"
    description = (
        "Sends frames with random source MAC addresses to fill the switch MAC "
        "address table. Unknown destinations are flooded to other ports. Use only with authorization."
    )
    default_interval = 0.0

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MacFloodingConfig:
        return MacFloodingConfig(iface=iface, count=count, interval=interval, dry_run=dry_run)

    def _run_attack(
        self,
        config: MacFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[FloodingStats], None],
    ) -> FloodingStats:
        return run_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: FloodingStats) -> str:
        return f"Frames sent: {stats.frames}"
