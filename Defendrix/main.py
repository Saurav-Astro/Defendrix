import sys
import argparse
import logging
import json
from pathlib import Path
from datetime import datetime

repo_root = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from SentinelLite.utils.error_handler import setup_global_exception_handler
from SentinelLite.engine.scanner_engine import ScannerEngine
from SentinelLite.reporting.report_generator import ReportGenerator

def setup_json_logger():
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"defendrix_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    logger = logging.getLogger("Defendrix")
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                log_record = {
                    "timestamp": self.formatTime(record, self.datefmt),
                    "level": record.levelname,
                    "message": record.getMessage()
                }
                return json.dumps(log_record)
                
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JsonFormatter())
        logger.addHandler(console_handler)
    
    return logger

def run_headless(args):
    logger = setup_json_logger()
    logger.info(f"Starting headless scan for target: {args.target}")
    
    engine = ScannerEngine()
    
    options = {
        "sqli": not args.no_sqli,
        "xss": not args.no_xss,
        "ssti": not args.no_ssti,
        "headers": not args.no_headers
    }
    
    auth = None
    if args.login_url or args.username or args.password:
        auth = {
            "login_url": args.login_url,
            "username": args.username,
            "password": args.password
        }
    
    logger.info("Initializing scanner engine...")
    try:
        result = engine.start_scan(args.target, options, auth)
        logger.info(f"Scan complete! Found {len(result.get('findings', []))} findings.")
        
        reporter = ReportGenerator()
        report_path = args.report_path or "defendrix_report_cli.html"
        findings = result.get("findings", [])
        reporter.generate_html(
            report_path,
            result.get("target"),
            result.get("surface"),
            findings
        )
        logger.info(f"HTML Report saved to {report_path}")
        
        if len(findings) > 0:
            sys.exit(2)
        else:
            sys.exit(0)
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    setup_global_exception_handler()
    
    parser = argparse.ArgumentParser(description="Defendrix - Web Vulnerability Scanner")
    parser.add_argument("--target", help="Target URL for headless scan")
    parser.add_argument("--headless", action="store_true", help="Run without GUI")
    parser.add_argument("--report-path", help="Path to save the HTML report")
    parser.add_argument("--no-sqli", action="store_true", help="Disable SQLi testing")
    parser.add_argument("--no-xss", action="store_true", help="Disable XSS testing")
    parser.add_argument("--no-ssti", action="store_true", help="Disable SSTI testing")
    parser.add_argument("--no-headers", action="store_true", help="Disable Header testing")
    parser.add_argument("--login-url", help="Login URL for authentication")
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    
    args, unknown = parser.parse_known_args()
    
    if args.headless and args.target:
        run_headless(args)
    elif args.headless and not args.target:
        print("Error: --target is required when running in --headless mode.")
        sys.exit(1)
    else:
        from PySide6.QtWidgets import QApplication
        from SentinelLite.gui.app import VulnerabilityScanner
        
        app = QApplication([])
        window = VulnerabilityScanner()
        window.show()
        app.exec()
