import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

repo_root = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from SentinelLite.gui.app import VulnerabilityScanner
from SentinelLite.utils.error_handler import setup_global_exception_handler


if __name__ == "__main__":
    setup_global_exception_handler()
    app = QApplication([])
    window = VulnerabilityScanner()
    window.show()
    app.exec()
