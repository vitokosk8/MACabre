"""Panel for the NDP neighbor cache exhaustion attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.ndp_neighbor_cache_exhaustion import (
    MAX_SOURCES,
    NdpNeighborCacheExhaustionConfig,
    NdpNeighborCacheExhaustionStats,
    run_ndp_neighbor_cache_exhaustion,
)
from macabre.gui.base_panel import AttackPanel


class NdpNeighborCacheExhaustionPanel(AttackPanel):
    title = "NDP Neighbor Cache Exhaustion"
    description = (
        "Sends Neighbor Solicitations from many new source addresses in a /64. Each one makes the target create "
        "a neighbor cache entry, which fills its table. Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Host whose cache is filled, e.g. 2001:db8:c0::1")
        form.addRow("Target:", self.target_edit)

        self.prefix_edit = QLineEdit("2001:db8:c0::/64")
        self.prefix_edit.setToolTip("The /64 the spoofed source addresses come from. The target must be inside it.")
        form.addRow("Prefix:", self.prefix_edit)

        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, MAX_SOURCES)
        self.count_spin.setValue(200)
        self.count_spin.setSuffix(" solicitation(s)")
        form.addRow("Solicitations:", self.count_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.target_edit, self.prefix_edit, self.count_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> NdpNeighborCacheExhaustionConfig:
        del count, interval  # this attack sends a fixed number of solicitations
        return NdpNeighborCacheExhaustionConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            target=self.target_edit.text().strip(),
            prefix=self.prefix_edit.text().strip(),
            count=self.count_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: NdpNeighborCacheExhaustionConfig,
        stop_event: threading.Event,
        on_progress: Callable[[NdpNeighborCacheExhaustionStats], None],
    ) -> NdpNeighborCacheExhaustionStats:
        return run_ndp_neighbor_cache_exhaustion(config, stop_event, on_progress)

    def _format_status(self, stats: NdpNeighborCacheExhaustionStats) -> str:
        return stats.status or f"Solicitations sent: {stats.frames}"
