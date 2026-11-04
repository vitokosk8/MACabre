"""Panel for the QinQ stacking abuse attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.qinq_stacking_abuse import (
    MAX_FRAMES,
    QinQStackingConfig,
    QinQStackingStats,
    run_qinq_stacking,
)
from macabre.gui.base_panel import AttackPanel


class QinQStackingPanel(AttackPanel):
    title = "QinQ / VLAN Stacking Abuse"
    description = (
        "Sends frames with an 802.1ad outer tag naming a provider VLAN, around the customer's 802.1Q tag. "
        "If the provider edge accepts the outer tag without setting its own, the customer picks the service. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Customer MAC, e.g. 02:00:00:00:00:30")
        form.addRow("Source MAC:", self.source_edit)

        self.provider_spin = QSpinBox()
        self.provider_spin.setRange(1, 4094)
        self.provider_spin.setValue(100)
        form.addRow("Provider VLAN (outer):", self.provider_spin)

        self.customer_spin = QSpinBox()
        self.customer_spin.setRange(1, 4094)
        self.customer_spin.setValue(20)
        form.addRow("Customer VLAN (inner):", self.customer_spin)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(1)
        self.frames_spin.setSuffix(" frame(s)")
        form.addRow("Frames:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_edit.setEnabled(enabled)
        self.provider_spin.setEnabled(enabled)
        self.customer_spin.setEnabled(enabled)
        self.frames_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> QinQStackingConfig:
        del count, interval  # this attack sends its frames once
        return QinQStackingConfig(
            iface=iface,
            provider_vid=self.provider_spin.value(),
            customer_vid=self.customer_spin.value(),
            source_mac=self.source_edit.text().strip(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: QinQStackingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[QinQStackingStats], None],
    ) -> QinQStackingStats:
        return run_qinq_stacking(config, stop_event, on_progress)

    def _format_status(self, stats: QinQStackingStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
