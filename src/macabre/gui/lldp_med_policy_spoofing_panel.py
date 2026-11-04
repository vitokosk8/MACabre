"""Panel for the LLDP-MED policy spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QComboBox, QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.lldp_med_policy_spoofing import (
    APPLICATION_TYPES,
    MAX_FRAMES,
    MAX_VLAN,
    LldpMedPolicySpoofingConfig,
    LldpMedPolicySpoofingStats,
    run_lldp_med_policy_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class LldpMedPolicySpoofingPanel(AttackPanel):
    title = "LLDP-MED Policy Spoofing"
    description = (
        "Advertises a fake LLDP-MED network policy: a VLAN, Layer 2 priority and DSCP for a voice or media "
        "application. An endpoint that accepts it may move its traffic there. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Advertised chassis MAC, e.g. 02:00:00:00:00:20")
        form.addRow("Source MAC:", self.source_edit)

        self.application_combo = QComboBox()
        self.application_combo.addItems(list(APPLICATION_TYPES))
        form.addRow("Application:", self.application_combo)

        self.tagged_check = QCheckBox("Tagged")
        self.tagged_check.setChecked(True)
        form.addRow("", self.tagged_check)

        self.vlan_spin = QSpinBox()
        self.vlan_spin.setRange(0, MAX_VLAN)
        self.vlan_spin.setValue(20)
        form.addRow("VLAN:", self.vlan_spin)

        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(0, 7)
        self.priority_spin.setValue(5)
        form.addRow("L2 priority:", self.priority_spin)

        self.dscp_spin = QSpinBox()
        self.dscp_spin.setRange(0, 63)
        self.dscp_spin.setValue(46)
        form.addRow("DSCP:", self.dscp_spin)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        self.frames_spin.setSuffix(" advertisement(s)")
        form.addRow("Advertisements:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.application_combo, self.tagged_check, self.vlan_spin,
                       self.priority_spin, self.dscp_spin, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> LldpMedPolicySpoofingConfig:
        del count  # the advertisement count is set in this panel
        tagged = self.tagged_check.isChecked()
        return LldpMedPolicySpoofingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            application=self.application_combo.currentText(),
            tagged=tagged,
            vlan_id=self.vlan_spin.value() if tagged else 0,
            priority=self.priority_spin.value(),
            dscp=self.dscp_spin.value(),
            frames=self.frames_spin.value(),
            interval=interval,
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: LldpMedPolicySpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[LldpMedPolicySpoofingStats], None],
    ) -> LldpMedPolicySpoofingStats:
        return run_lldp_med_policy_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: LldpMedPolicySpoofingStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
