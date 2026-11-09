"""Panel for the solicited Neighbor Advertisement spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QDoubleSpinBox, QFormLayout, QLineEdit

from macabre.attacks.neighbor_advertisement_spoofing import (
    MAX_TIMEOUT,
    SolicitedAdvertisementConfig,
    SolicitedAdvertisementStats,
    run_solicited_advertisement_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class NeighborAdvertisementSpoofingPanel(AttackPanel):
    title = "Neighbor Advertisement Spoofing"
    description = (
        "Waits for a Neighbor Solicitation for a target IPv6 address and answers it with a solicited Neighbor "
        "Advertisement from your MAC. The requester takes the first reply it gets, so this works when the real "
        "host is silent or slower. Unlike NDP Cache Poisoning, it does not overwrite valid entries. "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("IPv6 address to answer for, e.g. 2001:db8:c0::2")
        form.addRow("Target:", self.target_edit)

        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.5, MAX_TIMEOUT)
        self.timeout_spin.setValue(10.0)
        self.timeout_spin.setSuffix(" s")
        form.addRow("Listen for:", self.timeout_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.target_edit, self.timeout_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> SolicitedAdvertisementConfig:
        del count, interval  # this attack answers the solicitations it hears, up to one per solicitation
        return SolicitedAdvertisementConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            target=self.target_edit.text().strip(),
            timeout=self.timeout_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: SolicitedAdvertisementConfig,
        stop_event: threading.Event,
        on_progress: Callable[[SolicitedAdvertisementStats], None],
    ) -> SolicitedAdvertisementStats:
        return run_solicited_advertisement_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: SolicitedAdvertisementStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
