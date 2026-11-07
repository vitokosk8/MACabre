"""Panel for the MLD spoofing and flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.mld_spoofing_flooding import (
    MAX_GROUPS,
    MldSpoofingFloodingConfig,
    MldSpoofingFloodingStats,
    run_mld_spoofing_flooding,
)
from macabre.gui.base_panel import AttackPanel


class MldSpoofingFloodingPanel(AttackPanel):
    title = "MLD Spoofing / Flooding"
    description = (
        "Sends MLD Reports for IPv6 multicast groups you do not listen to. A switch that snoops MLD forwards "
        "those groups to your port (spoofing); many reports fill its group table (flooding). "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.base_edit = QLineEdit("ff0e::1000")
        self.base_edit.setToolTip("First group of the range, inside ff0e::/16.")
        form.addRow("Base group:", self.base_edit)

        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, MAX_GROUPS)
        self.count_spin.setValue(1)
        self.count_spin.setSuffix(" group(s)")
        self.count_spin.setToolTip("1 spoofs one membership; more floods the switch's group table.")
        form.addRow("Groups:", self.count_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.base_edit, self.count_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> MldSpoofingFloodingConfig:
        del count, interval  # this attack sends a fixed number of reports
        return MldSpoofingFloodingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            base_group=self.base_edit.text().strip(),
            count=self.count_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: MldSpoofingFloodingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[MldSpoofingFloodingStats], None],
    ) -> MldSpoofingFloodingStats:
        return run_mld_spoofing_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: MldSpoofingFloodingStats) -> str:
        return stats.status or f"Reports sent: {stats.reports}"
