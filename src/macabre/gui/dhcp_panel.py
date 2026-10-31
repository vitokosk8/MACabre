"""Configuration and execution panel for the DHCP starvation attack."""

from __future__ import annotations

import threading

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

from macabre.attacks.dhcp_starvation import DhcpStarvationConfig, run_starvation

AUTHORIZATION_TEXT = (
    "I confirm that I have explicit authorization to run DHCP stress tests "
    "on this network."
)


class _StarvationWorker(QThread):
    progress = Signal(int)
    failed = Signal(str)

    def __init__(self, config: DhcpStarvationConfig) -> None:
        super().__init__()
        self._config = config
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            run_starvation(self._config, self._stop, self.progress.emit)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            self.failed.emit(str(exc))


class DhcpStarvationPanel(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: _StarvationWorker | None = None
        self._build_ui()
        self._refresh_interfaces()

    # --- UI construction --------------------------------------------------

    def _build_ui(self) -> None:
        title = QLabel("<h2>DHCP starvation</h2>")
        warning = QLabel(
            "Sends DHCPDISCOVER messages with random MAC addresses to exhaust "
            "the server's address pool. Use only with authorization."
        )
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
        self.interval_spin.setValue(0.05)

        self.dry_run_check = QCheckBox("Generate frames only (do not send)")

        params = QGroupBox("Parameters")
        form = QFormLayout(params)
        form.addRow("Interface:", iface_row)
        form.addRow("Number of DISCOVER frames:", self.count_spin)
        form.addRow("Interval between frames:", self.interval_spin)
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

        config = DhcpStarvationConfig(
            iface=self.iface_combo.currentText(),
            count=self.count_spin.value(),
            interval=self.interval_spin.value(),
            dry_run=self.dry_run_check.isChecked(),
        )
        self._worker = _StarvationWorker(config)
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

    def _on_progress(self, generated: int) -> None:
        self.status_label.setText(f"DISCOVER frames generated: {generated}")

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

    def _log(self, message: str) -> None:
        self.log.appendPlainText(message)
