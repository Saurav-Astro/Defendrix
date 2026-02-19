from PySide6.QtWidgets import QApplication

from SentinelLite.gui.app import VulnerabilityScanner
from SentinelLite.utils.error_handler import setup_global_exception_handler


if __name__ == "__main__":
    setup_global_exception_handler()
    app = QApplication([])
    window = VulnerabilityScanner()
    window.show()
    app.exec()
