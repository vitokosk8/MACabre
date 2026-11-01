"""Panel for the DHCP offer flooding attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.dhcp_offer_flooding import MAX_OFFERS, OfferFloodConfig, OfferFloodStats, run_offer_flooding
from macabre.gui.base_panel import AttackPanel


class DhcpOfferFloodingPanel(AttackPanel):
    title = "DHCP Offer Flooding"
    description = (
        "Answers each client DISCOVER with a burst of OFFERs from invented servers, each with its own address "
        "and gateway. A client that takes the first offer may choose one of them. Runs until stopped. "
        "Use only with authorization."
    )
    default_interval = 1.0

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.network_edit = QLineEdit("192.168.0.0/24")
        self.network_edit.setToolTip("Pool the invented servers and addresses are drawn from.")
        form.addRow("Network:", self.network_edit)

        self.offers_spin = QSpinBox()
        self.offers_spin.setRange(1, MAX_OFFERS)
        self.offers_spin.setValue(10)
        self.offers_spin.setToolTip("OFFERs sent in answer to each DISCOVER.")
        form.addRow("Offers per DISCOVER:", self.offers_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        self.network_edit.setEnabled(enabled)
        self.offers_spin.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> OfferFloodConfig:
        del count, interval  # the flood answers DISCOVERs as they arrive, and runs until stopped
        return OfferFloodConfig(
            iface=iface,
            network=self.network_edit.text().strip() or "192.168.0.0/24",
            offers_per_discover=self.offers_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: OfferFloodConfig,
        stop_event: threading.Event,
        on_progress: Callable[[OfferFloodStats], None],
    ) -> OfferFloodStats:
        return run_offer_flooding(config, stop_event, on_progress)

    def _format_status(self, stats: OfferFloodStats) -> str:
        return stats.status or f"DISCOVERs answered: {stats.discovers}, offers sent: {stats.offers}"
