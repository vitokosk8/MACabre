"""Shared panel for running an attack: parameters, start/stop, status and log."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
from scapy.all import get_if_list

AUTHORIZATION_TEXT = (
    "I confirm that I have explicit authorization to run this test on this network."
)


class _AttackWorker(QThread):
    progress = Signal(object)  # attack statistics
    failed = Signal(str)

    def __init__(self, run: Callable[..., Any], config: Any) -> None:
        super().__init__()
        self._run_attack = run
        self._config = config
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            self._run_attack(self._config, self._stop, self.progress.emit)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            self.failed.emit(str(exc))


class AttackPanel(QWidget):
    """Base panel. Subclasses describe one attack through a few hooks."""

    title: str = ""
    description: str = ""
    default_interval: float = 0.05

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: _AttackWorker | None = None
        self._build_ui()
        self._refresh_interfaces()

    # --- hooks for subclasses ---------------------------------------------

    def _add_extra_controls(self, form: QFormLayout) -> None:
        """Add attack-specific controls to the parameters form."""

    def _set_extra_controls_enabled(self, enabled: bool) -> None:
        """Enable or disable attack-specific controls."""

    def _make_config(self, iface: str, count: int, interval: float, dry_run: bool) -> Any:
        raise NotImplementedError

    def _run_attack(self, config: Any, stop_event: threading.Event, on_progress: Callable) -> Any:
        raise NotImplementedError

    def _format_status(self, stats: Any) -> str:
        raise NotImplementedError

    # --- UI construction --------------------------------------------------

    def _build_ui(self) -> None:
        title = QLabel(f"<h2>{self.title}</h2>")
        warning = QLabel(self.description)
        warning.setWordWrap(True)

        self.iface_combo = QComboBox()
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._refresh_interfaces)
        iface_row = QHBoxLayout()
        iface_row.addWidget(self.iface_combo, 1)
        iface_row.addWidget(self.refresh_button)

        self.count_spin = QSpinBox()
        self.count_spin.setRange(0, 1_000_000)
        self.count_spin.setSpecialValueText("Unlimited")
        self.count_spin.setValue(0)

        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(0.0, 10.0)
        self.interval_spin.setDecimals(3)
        self.interval_spin.setSingleStep(0.01)
        self.interval_spin.setSuffix(" s")
        self.interval_spin.setValue(self.default_interval)

        self.dry_run_check = QCheckBox("Generate frames only (do not send)")

        params = QGroupBox("Parameters")
        form = QFormLayout(params)
        form.addRow("Interface:", iface_row)
        form.addRow("Number of frames:", self.count_spin)
        form.addRow("Interval between frames:", self.interval_spin)
        self._add_extra_controls(form)
        form.addRow("", self.dry_run_check)

        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self._start)
        self.stop_button.clicked.connect(self._stop)
        buttons = QHBoxLayout()
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch(1)

        self.status_label = QLabel("Stopped")
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(warning)
        layout.addWidget(params)
        layout.addLayout(buttons)
        layout.addWidget(self.status_label)
        layout.addWidget(self.log, 1)

    # --- actions ----------------------------------------------------------

    def _refresh_interfaces(self) -> None:
        current = self.iface_combo.currentText()
        self.iface_combo.clear()
        self.iface_combo.addItems(get_if_list())
        index = self.iface_combo.findText(current)
        if index >= 0:
            self.iface_combo.setCurrentIndex(index)

    def _start(self) -> None:
        if not self.iface_combo.currentText():
            QMessageBox.warning(self, "Missing interface", "Select a network interface.")
            return
        if not self._confirm_authorization():
            return

        try:
            config = self._make_config(
                self.iface_combo.currentText(),
                self.count_spin.value(),
                self.interval_spin.value(),
                self.dry_run_check.isChecked(),
            )
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid parameters", str(exc))
            return
        self._worker = _AttackWorker(self._run_attack, config)
        self._worker.progress.connect(self._on_progress)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_finished)

        mode = "frame generation only" if config.dry_run else "live sending"
        self._log(f"Starting on {config.iface} ({mode}).")
        self._set_running(True)
        self._worker.start()

    def _stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self._log("Stopping...")

    def _confirm_authorization(self) -> bool:
        answer = QMessageBox.question(
            self,
            "Confirm authorization",
            f"{AUTHORIZATION_TEXT}\n\nDo you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    # --- worker signals ---------------------------------------------------

    def _on_progress(self, stats: Any) -> None:
        self.status_label.setText(self._format_status(stats))

    def _on_failed(self, message: str) -> None:
        self._log(f"Error: {message}")
        QMessageBox.critical(self, "Error", message)

    def _on_finished(self) -> None:
        self._log("Finished.")
        self._set_running(False)
        self._worker = None

    # --- helpers ----------------------------------------------------------

    def _set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.iface_combo.setEnabled(not running)
        self.count_spin.setEnabled(not running)
        self.interval_spin.setEnabled(not running)
        self.dry_run_check.setEnabled(not running)
        self._set_extra_controls_enabled(not running)

    def _log(self, message: str) -> None:
        self.log.appendPlainText(message)
