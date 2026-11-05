"""Panel for the 802.1X identity spoofing attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.eapol_identity_spoofing import (
    MAX_TIMEOUT_SECONDS,
    EapolIdentitySpoofingConfig,
    EapolIdentitySpoofingStats,
    run_eapol_identity_spoofing,
)
from macabre.gui.base_panel import AttackPanel


class EapolIdentitySpoofingPanel(AttackPanel):
    title = "802.1X Identity Spoofing"
    description = (
        "Starts 802.1X authentication from this host's MAC and answers the identity request with names it does not "
        "own, without any proof. Shows whether the authenticator forwards the claimed identity to the server. "
        "Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Empty = a random MAC for each identity")
        form.addRow("Source MAC:", self.source_edit)

        self.identities_edit = QLineEdit()
        self.identities_edit.setPlaceholderText("Identities to claim, comma separated, e.g. bob, alice")
        form.addRow("Identities:", self.identities_edit)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, int(MAX_TIMEOUT_SECONDS))
        self.timeout_spin.setValue(3)
        self.timeout_spin.setSuffix(" s")
        self.timeout_spin.setToolTip("How long to wait for each identity request.")
        form.addRow("Wait:", self.timeout_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.source_edit.setEnabled(enabled)
        self.identities_edit.setEnabled(enabled)
        self.timeout_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> EapolIdentitySpoofingConfig:
        del count, interval  # one exchange per identity, each with the wait time above
        identities = tuple(i.strip() for i in self.identities_edit.text().split(",") if i.strip())
        return EapolIdentitySpoofingConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            identities=identities,
            response_timeout=float(self.timeout_spin.value()),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: EapolIdentitySpoofingConfig,
        stop_event: threading.Event,
        on_progress: Callable[[EapolIdentitySpoofingStats], None],
    ) -> EapolIdentitySpoofingStats:
        return run_eapol_identity_spoofing(config, stop_event, on_progress)

    def _format_status(self, stats: EapolIdentitySpoofingStats) -> str:
        return stats.status or (
            f"Exchanges: {stats.exchanges}, identity requests seen: {stats.requests_seen}, responses sent: {stats.responses}"
        )
