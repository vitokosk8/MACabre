"""Panel for the NDP cache poisoning attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.ndp_cache_poisoning import (
    MAX_FRAMES,
    NdpCachePoisoningConfig,
    NdpCachePoisoningStats,
    run_ndp_cache_poisoning,
)
from macabre.gui.base_panel import AttackPanel


class NdpCachePoisoningPanel(AttackPanel):
    title = "NDP Cache Poisoning"
    description = (
        "Sends unsolicited Neighbor Advertisements that rebind a target IPv6 address to your MAC. Hosts that "
        "accept them replace the stored entry, and their traffic for that address goes to you. "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("IPv6 address whose entry is rebound, e.g. 2001:db8:c0::2")
        form.addRow("Target:", self.target_edit)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        self.frames_spin.setSuffix(" advertisement(s)")
        form.addRow("Advertisements:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.target_edit, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> NdpCachePoisoningConfig:
        del count, interval  # this attack sends a fixed number of advertisements
        return NdpCachePoisoningConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            target=self.target_edit.text().strip(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: NdpCachePoisoningConfig,
        stop_event: threading.Event,
        on_progress: Callable[[NdpCachePoisoningStats], None],
    ) -> NdpCachePoisoningStats:
        return run_ndp_cache_poisoning(config, stop_event, on_progress)

    def _format_status(self, stats: NdpCachePoisoningStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
