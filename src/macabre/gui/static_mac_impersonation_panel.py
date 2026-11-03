"""Panel for the static MAC impersonation attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.static_mac_impersonation import (
    MAX_RATE,
    StaticMacImpersonationConfig,
    StaticMacImpersonationStats,
    run_static_mac_impersonation,
)
from macabre.gui.base_panel import AttackPanel


class StaticMacImpersonationPanel(AttackPanel):
    title = "Static MAC Impersonation"
    description = (
        "Sends frames whose source is a MAC address registered with a static entry on another port. "
        "The switch keeps its binding, so the question is whether it still accepts and forwards the frames. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Registered MAC, e.g. 02:00:00:00:00:50")
        form.addRow("Registered MAC:", self.source_edit)

        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, int(MAX_RATE))
        self.rate_spin.setValue(10)
        self.rate_spin.setSuffix(" frames/s")
        form.addRow("Rate:", self.rate_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_edit.setEnabled(enabled)
        self.rate_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> StaticMacImpersonationConfig:
        del interval  # the rate sets the timing for this attack
        return StaticMacImpersonationConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            rate=float(self.rate_spin.value()),
            count=count,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: StaticMacImpersonationConfig,
        stop_event: threading.Event,
        on_progress: Callable[[StaticMacImpersonationStats], None],
    ) -> StaticMacImpersonationStats:
        return run_static_mac_impersonation(config, stop_event, on_progress)

    def _format_status(self, stats: StaticMacImpersonationStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
