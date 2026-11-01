"""Panel for the DTP negotiation audit."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QFormLayout

from macabre.attacks.dtp_audit import DtpAuditConfig, DtpAuditStats, run_dtp_audit
from macabre.gui.base_panel import AttackPanel


class DtpAuditPanel(AttackPanel):
    title = "DTP negotiation audit"
    description = (
        "Listens for the DTP frames this port's switch sends and reports the trunk status, encapsulation "
        "and domain they advertise. Optionally sends one negotiation frame and reports whether the port "
        "answers with a trunk. Runs until stopped. The status values follow the public DTP description, "
        "not a checked switch. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.probe_check = QCheckBox("Send one negotiation frame and watch for a trunk answer")
        self.probe_check.setChecked(True)
        form.addRow("Probe:", self.probe_check)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.probe_check.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> DtpAuditConfig:
        del count, interval  # the audit listens until it is stopped
        return DtpAuditConfig(iface=iface, probe=self.probe_check.isChecked(), dry_run=dry_run)

    def _run_attack(
        self,
        config: DtpAuditConfig,
        stop_event: threading.Event,
        on_progress: Callable[[DtpAuditStats], None],
    ) -> DtpAuditStats:
        return run_dtp_audit(config, stop_event, on_progress)

    def _format_status(self, stats: DtpAuditStats) -> str:
        if stats.status:
            return stats.status
        return f"DTP frames heard: {stats.frames_seen}"
