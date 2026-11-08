"""Panel for the SLAAC configuration abuse attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.slaac_configuration_abuse import (
    MAX_FRAMES,
    MAX_HOP_LIMIT,
    MAX_MTU,
    MIN_MTU,
    SlaacConfigurationAbuseConfig,
    SlaacConfigurationAbuseStats,
    run_slaac_configuration_abuse,
)
from macabre.attacks.rogue_router_advertisement import MAX_ROUTER_LIFETIME
from macabre.gui.base_panel import AttackPanel


class SlaacConfigurationAbusePanel(AttackPanel):
    title = "SLAAC Configuration Abuse"
    description = (
        "Sends Router Advertisements that change the MTU and the current hop limit hosts apply to their "
        "traffic. Hosts that accept them use the forged values for every packet. "
        "Use only with authorization, on a segment you control."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Your MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Source MAC:", self.source_edit)

        self.mtu_spin = QSpinBox()
        self.mtu_spin.setRange(MIN_MTU, MAX_MTU)
        self.mtu_spin.setValue(1280)
        self.mtu_spin.setSuffix(" bytes")
        form.addRow("MTU:", self.mtu_spin)

        self.hop_spin = QSpinBox()
        self.hop_spin.setRange(1, MAX_HOP_LIMIT)
        self.hop_spin.setValue(32)
        form.addRow("Hop limit:", self.hop_spin)

        self.lifetime_spin = QSpinBox()
        self.lifetime_spin.setRange(1, MAX_ROUTER_LIFETIME)
        self.lifetime_spin.setValue(1800)
        self.lifetime_spin.setSuffix(" s")
        form.addRow("Router lifetime:", self.lifetime_spin)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        self.frames_spin.setSuffix(" advertisement(s)")
        form.addRow("Advertisements:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.mtu_spin, self.hop_spin, self.lifetime_spin, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> SlaacConfigurationAbuseConfig:
        del count, interval  # this attack sends a fixed number of advertisements
        return SlaacConfigurationAbuseConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            mtu=self.mtu_spin.value(),
            hop_limit=self.hop_spin.value(),
            router_lifetime=self.lifetime_spin.value(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: SlaacConfigurationAbuseConfig,
        stop_event: threading.Event,
        on_progress: Callable[[SlaacConfigurationAbuseStats], None],
    ) -> SlaacConfigurationAbuseStats:
        return run_slaac_configuration_abuse(config, stop_event, on_progress)

    def _format_status(self, stats: SlaacConfigurationAbuseStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
