"""Panel for the root bridge takeover attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QSpinBox

from macabre.attacks.bpdu_spoofing import MAX_PRIORITY, PRIORITY_STEP
from macabre.attacks.root_bridge_takeover import (
    RootBridgeTakeoverConfig,
    RootBridgeTakeoverStats,
    run_root_bridge_takeover,
)
from macabre.gui.base_panel import AttackPanel


class RootBridgeTakeoverPanel(AttackPanel):
    title = "Root Bridge Takeover"
    description = (
        "Advertises this interface's bridge as the spanning-tree root and keeps refreshing the claim. "
        "A switch that accepts it keeps its root port toward this port while the claim lasts. "
        "Use only with authorization."
    )
    default_interval = 2.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(0, MAX_PRIORITY)
        self.priority_spin.setSingleStep(PRIORITY_STEP)
        self.priority_spin.setValue(0)
        self.priority_spin.setToolTip("Bridge priority claimed for the root (multiple of 4096; lower wins).")
        form.addRow("Claimed priority:", self.priority_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.priority_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RootBridgeTakeoverConfig:
        return RootBridgeTakeoverConfig(
            iface=iface,
            priority=self.priority_spin.value(),
            count=count,
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RootBridgeTakeoverConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RootBridgeTakeoverStats], None],
    ) -> RootBridgeTakeoverStats:
        return run_root_bridge_takeover(config, stop_event, on_progress)

    def _format_status(self, stats: RootBridgeTakeoverStats) -> str:
        return stats.status or f"Root claims sent: {stats.frames}"
