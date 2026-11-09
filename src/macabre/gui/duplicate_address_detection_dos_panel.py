"""Panel for the Duplicate Address Detection DoS attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.duplicate_address_detection_dos import (
    MAX_FRAMES,
    DuplicateAddressDetectionDosConfig,
    DuplicateAddressDetectionDosStats,
    run_duplicate_address_detection_dos,
)
from macabre.gui.base_panel import AttackPanel


class DuplicateAddressDetectionDosPanel(AttackPanel):
    title = "Duplicate Address Detection DoS"
    description = (
        "Answers the Duplicate Address Detection of a new host with forged Neighbor Advertisements for the "
        "address it is about to configure. The host marks the address as duplicate and does not use it. "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Tentative IPv6 address to block, e.g. 2001:db8:c0::50")
        form.addRow("Target:", self.target_edit)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(30)
        self.frames_spin.setSuffix(" advertisement(s)")
        form.addRow("Advertisements:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.target_edit, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> DuplicateAddressDetectionDosConfig:
        del count, interval  # this attack sends a fixed number of advertisements
        return DuplicateAddressDetectionDosConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            target=self.target_edit.text().strip(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: DuplicateAddressDetectionDosConfig,
        stop_event: threading.Event,
        on_progress: Callable[[DuplicateAddressDetectionDosStats], None],
    ) -> DuplicateAddressDetectionDosStats:
        return run_duplicate_address_detection_dos(config, stop_event, on_progress)

    def _format_status(self, stats: DuplicateAddressDetectionDosStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
