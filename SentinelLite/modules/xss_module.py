from SentinelLite.models.finding import Finding
from SentinelLite.engine.severity_classifier import SeverityClassifier


class XSSModule:
    def __init__(self, payloads):
        self.payloads = payloads
        self.classifier = SeverityClassifier()

    def run(self, url, request_manager, mutation_engine, analyzer, forms=None):
        findings = []
        
        findings.extend(self._test_url_parameters(url, request_manager, mutation_engine, analyzer))
        
        if forms:
            findings.extend(self._test_forms(forms, request_manager, analyzer))
        
        return findings

    def _test_url_parameters(self, url, request_manager, mutation_engine, analyzer):
        findings = []
        baseline = request_manager.get(url)
        if not baseline:
            return findings

        for mutation in mutation_engine.generate_mutations(url, self.payloads):
            response = request_manager.get(mutation["url"])
            if not response:
                continue

            analysis = analyzer.analyze(baseline, response, mutation["payload"])
            severity, confidence = self.classifier.xss(analysis)
            if severity:
                findings.append(
                    Finding(
                        type="XSS",
                        owasp_category="A03:2021 - Injection",
                        severity=severity,
                        confidence=confidence,
                        endpoint=url,
                        payload=mutation["payload"],
                        details="Cross-Site Scripting vulnerability detected. Unencoded payload reflected in response.",
                        source="XSSModule",
                    ).to_dict()
                )

        return findings

    def _test_forms(self, forms, request_manager, analyzer):
        findings = []
        
        for form in forms:
            action_url = form.get("action")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            if not inputs:
                continue
            
            for input_name in inputs:
                form_findings = self._test_form_input(
                    action_url, method, inputs, input_name, 
                    request_manager, analyzer
                )
                findings.extend(form_findings)
        
        return findings

    def _test_form_input(self, action_url, method, all_inputs, target_input, request_manager, analyzer):
        findings = []
        
        for payload in self.payloads:
            form_data = {}
            for inp in all_inputs:
                if inp == target_input:
                    form_data[inp] = payload
                else:
                    form_data[inp] = "test"
            
            if method == "POST":
                response = request_manager.post(action_url, data=form_data)
            else:
                response = request_manager.get(action_url, params=form_data)
            
            if not response:
                continue
            
            if payload in response.text:
                findings.append(
                    Finding(
                        type="XSS",
                        owasp_category="A03:2021 - Injection",
                        severity="High",
                        confidence="Medium",
                        endpoint=action_url,
                        payload=payload,
                        details=f"XSS vulnerability detected in form field '{target_input}'. Payload was reflected in response.",
                        source="XSSModule",
                    ).to_dict()
                )
        
        return findings
