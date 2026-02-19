from SentinelLite.config import settings
from SentinelLite.engine.mutation_engine import MutationEngine
from SentinelLite.engine.request_manager import RequestManager
from SentinelLite.engine.response_analyzer import ResponseAnalyzer
from SentinelLite.engine.result_aggregator import ResultAggregator
from SentinelLite.engine.crawler import Crawler
from SentinelLite.engine.attack_surface_mapper import AttackSurfaceMapper
from SentinelLite.engine.auth_handler import AuthHandler
from SentinelLite.intelligence.virustotal_client import VirusTotalClient
from SentinelLite.modules.header_module import HeaderModule
from SentinelLite.modules.sqli_module import SQLiModule
from SentinelLite.modules.xss_module import XSSModule
from SentinelLite.modules.ssti_module import SSTIModule


class ScannerEngine:
    def __init__(self, request_manager=None, mutation_engine=None, analyzer=None, threat_client=None):
        self.request_manager = request_manager or RequestManager(
            timeout=settings.DEFAULT_TIMEOUT,
            verify=settings.VERIFY_SSL,
        )
        self.mutation_engine = mutation_engine or MutationEngine()
        self.analyzer = analyzer or ResponseAnalyzer(
            error_patterns=settings.SQL_ERROR_PATTERNS,
            length_delta_threshold=settings.LENGTH_DELTA_THRESHOLD,
        )
        self.aggregator = ResultAggregator()
        self.threat_client = threat_client or VirusTotalClient(timeout=settings.DEFAULT_TIMEOUT)
        self.surface_mapper = AttackSurfaceMapper()
        self.modules = {
            "sqli": SQLiModule(settings.SQLI_PAYLOADS),
            "xss": XSSModule(settings.XSS_PAYLOADS),
            "ssti": SSTIModule(["{{7*7}}"]),
            "headers": HeaderModule(settings.REQUIRED_HEADERS),
        }

    def start_scan(self, url, options=None, auth=None):
        options = options or {"sqli": True, "xss": True, "ssti": True, "headers": True}

        if auth:
            auth_handler = AuthHandler(auth.get("login_url"), auth.get("username"), auth.get("password"))
            auth_handler.authenticate(self.request_manager)

        crawler = Crawler(self.request_manager.session, url, max_depth=2)
        crawl_result = crawler.crawl()
        endpoints = crawl_result["endpoints"]
        forms = crawl_result["forms"]
        parameters = crawl_result["parameters"]
        surface = self.surface_mapper.map(endpoints, forms, parameters)

        findings = []
        threat_finding = self.threat_client.check_url_reputation(url)
        if threat_finding:
            findings.append(threat_finding)

        module_results = []
        
        for endpoint in endpoints:
            if options.get("sqli"):
                module_results.append(
                    self.modules["sqli"].run(endpoint, self.request_manager, self.mutation_engine, self.analyzer)
                )
            if options.get("xss"):
                module_results.append(
                    self.modules["xss"].run(endpoint, self.request_manager, self.mutation_engine, self.analyzer)
                )
            if options.get("ssti"):
                module_results.append(
                    self.modules["ssti"].run(endpoint, self.request_manager, self.mutation_engine, self.analyzer)
                )
            if options.get("headers"):
                module_results.append(
                    self.modules["headers"].run(endpoint, self.request_manager)
                )
        
        if forms:
            print(f"[*] Testing {len(forms)} forms for vulnerabilities...")
            if options.get("sqli"):
                print(f"[*] Testing forms for SQL injection...")
                sqli_form_findings = self.modules["sqli"].run(
                    url, 
                    self.request_manager, 
                    self.mutation_engine, 
                    self.analyzer, 
                    forms=forms
                )
                module_results.append(sqli_form_findings)
            
            if options.get("xss"):
                print(f"[*] Testing forms for XSS...")
                xss_form_findings = self.modules["xss"].run(
                    url, 
                    self.request_manager, 
                    self.mutation_engine, 
                    self.analyzer,
                    forms=forms
                )
                module_results.append(xss_form_findings)

        return {
            "findings": self.aggregator.combine(findings, *module_results),
            "surface": surface,
            "target": url,
        }
