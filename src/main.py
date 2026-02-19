import sys
from PySide6.QtWidgets import QApplication

from gui.app import CryptoSafeApp


def main():
    app = QApplication(sys.argv)
    cs = CryptoSafeApp()
    raise SystemExit(cs.run(app))


if __name__ == "__main__":
    main()
