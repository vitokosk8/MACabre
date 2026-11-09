"""Panel for the Neighbor Solicitation spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.neighbor_solicitation_spoofing import (
    MAX_FRAMES,
    NeighborSolicitationSpoofingConfig,
    NeighborSolicitationSpoofingStats,
    run_neighbor_solicitation_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class NeighborSolicitationSpoofingPanel(AttackPanel):
    title = "Neighbor Solicitation Spoofing"
    description = (
        "Sends Neighbor Solicitations that claim a target IPv6 address with your MAC in the Source "
        "Link-Layer Address option. A victim that stores that option records your MAC for the target "
        "without any reply. Leave the receiver empty to aim at the target's own solicited-node group. "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("IPv6 address to impersonate, e.g. 2001:db8:c0::2")
        form.addRow("Target:", self.target_edit)

        self.receiver_edit = QLineEdit()
        self.receiver_edit.setPlaceholderText("Victim IPv6 address (optional)")
        form.addRow("Receiver:", self.receiver_edit)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        self.frames_spin.setSuffix(" solicitation(s)")
        form.addRow("Solicitations:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.target_edit, self.receiver_edit, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> NeighborSolicitationSpoofingConfig:
        del count, interval  # this attack sends a fixed number of solicitations
        return NeighborSolicitationSpoofingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            target=self.target_edit.text().strip(),
            receiver=self.receiver_edit.text().strip(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: NeighborSolicitationSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[NeighborSolicitationSpoofingStats], None],
    ) -> NeighborSolicitationSpoofingStats:
        return run_neighbor_solicitation_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: NeighborSolicitationSpoofingStats) -> str:
        return stats.status or f"Solicitations sent: {stats.frames}"
