"""Entry point: `python -m macabre` or the `macabre` command."""

import sys


def main() -> int:
    from PySide6.QtWidgets import QApplication

    from macabre.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("macabre")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
