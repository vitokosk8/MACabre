"""Panel for the rogue router advertisement attack."""

from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLineEdit, QSpinBox

from macabre.attacks.rogue_router_advertisement import (
    MAX_FRAMES,
    MAX_ROUTER_LIFETIME,
    RogueRouterAdvertisementConfig,
    RogueRouterAdvertisementStats,
    run_rogue_router_advertisement,
)
from macabre.gui.base_panel import AttackPanel


class RogueRouterAdvertisementPanel(AttackPanel):
    title = "Rogue Router Advertisement"
    description = (
        "Sends IPv6 Router Advertisements from this host, announcing it as a default router for a /64 prefix. "
        "Listening hosts that accept RAs may add it as their default router and configure SLAAC addresses from "
        "the prefix. Use only with authorization."
    )
    default_interval = 1.0
    show_frame_controls = False

    def _add_extra_controls(self, form: QFormLayout) -> None:
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Advertised router MAC, e.g. 02:00:00:00:10:03")
        form.addRow("Router MAC:", self.source_edit)

        self.prefix_edit = QLineEdit("2001:db8:bad::/64")
        self.prefix_edit.setToolTip("The /64 prefix advertised for SLAAC.")
        form.addRow("Prefix:", self.prefix_edit)

        self.lifetime_spin = QSpinBox()
        self.lifetime_spin.setRange(1, MAX_ROUTER_LIFETIME)
        self.lifetime_spin.setValue(1800)
        self.lifetime_spin.setSuffix(" s")
        self.lifetime_spin.setToolTip("How long hosts keep this router as their default.")
        form.addRow("Router lifetime:", self.lifetime_spin)

        self.frames_spin = QSpinBox()
        self.frames_spin.setRange(1, MAX_FRAMES)
        self.frames_spin.setValue(3)
        self.frames_spin.setSuffix(" RA(s)")
        form.addRow("Advertisements:", self.frames_spin)

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.source_edit, self.prefix_edit, self.lifetime_spin, self.frames_spin):
            widget.setEnabled(enabled)

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> RogueRouterAdvertisementConfig:
        del count, interval  # this attack sends a fixed number of advertisements
        return RogueRouterAdvertisementConfig(
            iface=iface,
            source_mac=self.source_edit.text().strip(),
            prefix=self.prefix_edit.text().strip(),
            router_lifetime=self.lifetime_spin.value(),
            frames=self.frames_spin.value(),
            dry_run=dry_run,
        )

    def _run_attack(
        self,
        config: RogueRouterAdvertisementConfig,
        stop_event: threading.Event,
        on_progress: Callable[[RogueRouterAdvertisementStats], None],
    ) -> RogueRouterAdvertisementStats:
        return run_rogue_router_advertisement(config, stop_event, on_progress)

    def _format_status(self, stats: RogueRouterAdvertisementStats) -> str:
        return stats.status or f"Advertisements sent: {stats.frames}"
