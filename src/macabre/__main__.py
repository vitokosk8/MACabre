"""Entry point: `python -m macabre` or the `macabre` command."""

import sys


def main() -> int:
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    from macabre.gui.icons import app_icon
    from macabre.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("MACabre")
    # Lets Linux desktops match the running window with macabre.desktop.
    QGuiApplication.setDesktopFileName("macabre")
    app.setWindowIcon(app_icon())
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
