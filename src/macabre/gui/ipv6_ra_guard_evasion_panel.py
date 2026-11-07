"""Panel for the IPv6 RA Guard evasion attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QComboBox, QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.ipv6_ra_guard_evasion import (
    MAX_FRAMES,
    VARIANTS,
    RaGuardEvasionConfig,
    RaGuardEvasionStats,
    run_ra_guard_evasion,
)
from macabre.gui.base_panel import AttackPanel

VARIANT_LABELS = {
    "plain": "Plain RA (control)",
    "destination_options": "Behind Destination Options header",
    "fragmented": "Fragmented (two fragments)",
}


class Ipv6RaGuardEvasionPanel(AttackPanel):
    title = "IPv6 RA Guard Evasion"
    description = (
        "Sends Router Advertisements in forms an RA Guard filter may not parse: behind an extension header, or "
        "split across fragments. Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.variant_combo = QComboBox()
        for variant in VARIANTS:
            self.variant_combo.addItem(VARIANT_LABELS[variant], variant)
        form.addRow("Form:", self.variant_combo)

        self.prefix_edit = QLineEdit("2001:db8:bad::/64")
        form.addRow("Prefix:", self.prefix_edit)

        self.lifetime_spin = QSpinBox()
        self.lifetime_spin.setRange(1, 65535)
        self.lifetime_spin.setValue(1800)
        self.lifetime_spin.setSuffix(" s")
        form.addRow("Router lifetime:", self.lifetime_spin)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        form.addRow("Rounds:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.variant_combo, self.prefix_edit,
                       self.lifetime_spin, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RaGuardEvasionConfig:
        del count, interval  # this attack sends a fixed number of rounds
        return RaGuardEvasionConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            variant=self.variant_combo.currentData(),
            prefix=self.prefix_edit.text().strip(),
            router_lifetime=self.lifetime_spin.value(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RaGuardEvasionConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RaGuardEvasionStats], None],
    ) -> RaGuardEvasionStats:
        return run_ra_guard_evasion(config, stop_event, on_progress)

    def _format_status(self, stats: RaGuardEvasionStats) -> str:
        return stats.status or f"Frames sent: {stats.frames}"
