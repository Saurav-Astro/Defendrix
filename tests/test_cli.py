import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Ensure repo root is in sys.path so we can import Defendrix
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# Import the run_headless function
from Defendrix.main import run_headless

class FakeArgs:
    def __init__(self, target="http://test.com", headless=True, report_path=None, 
                 no_sqli=False, no_xss=False, no_ssti=False, no_headers=False,
                 login_url=None, username=None, password=None):
        self.target = target
        self.headless = headless
        self.report_path = report_path
        self.no_sqli = no_sqli
        self.no_xss = no_xss
        self.no_ssti = no_ssti
        self.no_headers = no_headers
        self.login_url = login_url
        self.username = username
        self.password = password

class TestHeadlessCLI(unittest.TestCase):
    
    @patch('Defendrix.main.ScannerEngine')
    @patch('Defendrix.main.ReportGenerator')
    def test_run_headless_no_findings_exits_0(self, MockReportGenerator, MockScannerEngine):
        mock_engine_instance = MockScannerEngine.return_value
        mock_engine_instance.start_scan.return_value = {
            "target": "http://test.com",
            "surface": {},
            "findings": []
        }
        
        args = FakeArgs()
        
        with self.assertRaises(SystemExit) as cm:
            run_headless(args)
            
        self.assertEqual(cm.exception.code, 0)
        MockReportGenerator.return_value.generate_html.assert_called_once()
        
    @patch('Defendrix.main.ScannerEngine')
    @patch('Defendrix.main.ReportGenerator')
    def test_run_headless_with_findings_exits_2(self, MockReportGenerator, MockScannerEngine):
        mock_engine_instance = MockScannerEngine.return_value
        mock_engine_instance.start_scan.return_value = {
            "target": "http://test.com",
            "surface": {},
            "findings": [{"type": "SQLi"}] 
        }
        
        args = FakeArgs()
        
        with self.assertRaises(SystemExit) as cm:
            run_headless(args)
            
        self.assertEqual(cm.exception.code, 2)
        
    @patch('Defendrix.main.ScannerEngine')
    def test_run_headless_engine_crash_exits_1(self, MockScannerEngine):
        mock_engine_instance = MockScannerEngine.return_value
        mock_engine_instance.start_scan.side_effect = Exception("Test engine crash")
        
        args = FakeArgs()
        
        with self.assertRaises(SystemExit) as cm:
            run_headless(args)
            
        self.assertEqual(cm.exception.code, 1)

if __name__ == '__main__':
    unittest.main()
