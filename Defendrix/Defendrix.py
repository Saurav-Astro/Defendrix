"""
Defendrix - Advanced Web Application Vulnerability Scanner
Complete vulnerability scanning with threat intelligence integration and payload injection
"""

import sys
import os
from pathlib import Path

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    os.system('chcp 65001 >nul 2>&1')
    sys.stdout.reconfigure(encoding='utf-8')

# Add parent directory to path to import SentinelLite modules
repo_root = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from PySide6.QtWidgets import QApplication
from SentinelLite.gui.app import VulnerabilityScanner
from SentinelLite.utils.error_handler import setup_global_exception_handler


def main():
    """Main entry point for Defendrix application"""
    print("=" * 70)
    print("DEFENDRIX - Advanced Web Application Vulnerability Scanner")
    print("=" * 70)
    print("Features:")
    print("  [*] SQL Injection Detection")
    print("  [*] Cross-Site Scripting (XSS) Detection")
    print("  [*] Server-Side Template Injection (SSTI) Detection")
    print("  [*] Security Headers Analysis")
    print("  [*] External Threat Intelligence Integration")
    print("  [*] Attack Surface Mapping")
    print("  [*] Professional OWASP-Compliant Reports")
    print("  [*] Automated Payload Injection Module")
    print("=" * 70)
    print("Launching GUI...")
    print()
    
    # Setup global exception handler
    setup_global_exception_handler()
    
    # Create and launch application
    app = QApplication(sys.argv)
    app.setApplicationName("Defendrix")
    app.setOrganizationName("Defendrix Security")
    
    window = VulnerabilityScanner()
    window.show()
    
    print("✓ GUI Initialized Successfully")
    print("✓ Threat Intelligence Integration Active")
    print("✓ Payload Injection Module Ready")
    print("\nApplication Ready! Use the GUI to start scanning.\n")
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
