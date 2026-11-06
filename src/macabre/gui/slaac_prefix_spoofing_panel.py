"""Panel for the SLAAC prefix spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.slaac_prefix_spoofing import (
    MAX_FRAMES,
    MAX_LIFETIME,
    SlaacPrefixSpoofingConfig,
    SlaacPrefixSpoofingStats,
    run_slaac_prefix_spoofing,
)
from macabre.gui.base_panel import AttackPanel

# QSpinBox holds signed 32-bit values, so the GUI caps lifetimes below the module's maximum.
SPIN_MAX_LIFETIME = min(MAX_LIFETIME, 2**31 - 1)


class SlaacPrefixSpoofingPanel(AttackPanel):
    title = "SLAAC Prefix Spoofing"
    description = (
        "Sends Router Advertisements with router lifetime 0 and a fraudulent /64 for autoconfiguration. "
        "Hosts that accept it configure addresses in that prefix without your host becoming their router. "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.prefix_edit = QLineEdit("2001:db8:bad:1::/64")
        self.prefix_edit.setToolTip("The fraudulent /64 hosts will configure addresses in.")
        form.addRow("Prefix:", self.prefix_edit)

        self.valid_spin = QSpinBox()
        self.valid_spin.setRange(1, SPIN_MAX_LIFETIME)
        self.valid_spin.setValue(86400)
        self.valid_spin.setSuffix(" s")
        form.addRow("Valid lifetime:", self.valid_spin)

        self.preferred_spin = QSpinBox()
        self.preferred_spin.setRange(0, SPIN_MAX_LIFETIME)
        self.preferred_spin.setValue(14400)
        self.preferred_spin.setSuffix(" s")
        form.addRow("Preferred lifetime:", self.preferred_spin)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        self.frames_spin.setSuffix(" advertisement(s)")
        form.addRow("Advertisements:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.prefix_edit, self.valid_spin, self.preferred_spin, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> SlaacPrefixSpoofingConfig:
        del count, interval  # this attack sends a fixed number of advertisements
        return SlaacPrefixSpoofingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            prefix=self.prefix_edit.text().strip(),
            valid_lifetime=self.valid_spin.value(),
            preferred_lifetime=self.preferred_spin.value(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: SlaacPrefixSpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[SlaacPrefixSpoofingStats], None],
    ) -> SlaacPrefixSpoofingStats:
        return run_slaac_prefix_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: SlaacPrefixSpoofingStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
