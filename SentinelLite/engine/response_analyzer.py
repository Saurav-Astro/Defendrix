class ResponseAnalyzer:
    def __init__(self, error_patterns=None, length_delta_threshold=120):
        self.error_patterns = [pattern.lower() for pattern in (error_patterns or [])]
        self.length_delta_threshold = length_delta_threshold

    def analyze(self, baseline, mutated, payload):
        if not baseline or not mutated:
            return {
                "status_change": False,
                "length_delta": 0,
                "sql_error": False,
                "reflected": False,
                "ssti_eval": False,
                "auth_bypass": False,
                "redirect": False,
                "reason": ""
            }

        baseline_text = baseline.text or ""
        mutated_text = mutated.text or ""

        status_change = baseline.status_code != mutated.status_code
        length_delta = abs(len(mutated_text) - len(baseline_text))
        sql_error = any(pattern in mutated_text.lower() for pattern in self.error_patterns)
        reflected = payload in mutated_text
        ssti_eval = "49" in mutated_text if payload == "{{7*7}}" else False
        
        auth_bypass = self._detect_auth_bypass(baseline, mutated, payload)
        
        redirect = mutated.status_code in [301, 302, 303, 307, 308]
        
        reason = self._build_reason(sql_error, auth_bypass, redirect, status_change, length_delta)

        return {
            "status_change": status_change,
            "length_delta": length_delta,
            "sql_error": sql_error,
            "reflected": reflected,
            "ssti_eval": ssti_eval,
            "auth_bypass": auth_bypass,
            "redirect": redirect,
            "reason": reason
        }

    def _detect_auth_bypass(self, baseline, mutated, payload):
        baseline_text = baseline.text.lower()
        mutated_text = mutated.text.lower()
        
        success_indicators = [
            "welcome", "logout", "account", "profile", "dashboard",
            "logged in", "sign out", "my account", "balance", 
            "transactions", "settings", "admin", "user"
        ]
        
        failure_indicators = [
            "login failed", "invalid", "incorrect", "authentication failed",
            "access denied", "unauthorized", "login again", "try again"
        ]
        
        baseline_has_failure = any(indicator in baseline_text for indicator in failure_indicators)
        
        mutated_has_success = any(indicator in mutated_text for indicator in success_indicators)
        
        mutated_lacks_failure = baseline_has_failure and not any(indicator in mutated_text for indicator in failure_indicators)
        
        redirect_change = baseline.status_code != mutated.status_code and mutated.status_code in [301, 302, 303]
        significant_change = abs(len(mutated_text) - len(baseline_text)) > 500
        
        return (mutated_has_success and not baseline_has_failure) or \
               (mutated_lacks_failure and significant_change) or \
               (redirect_change and mutated.status_code == 302)

    def _build_reason(self, sql_error, auth_bypass, redirect, status_change, length_delta):
        reasons = []
        
        if sql_error:
            reasons.append("SQL error pattern detected in response")
        
        if auth_bypass:
            reasons.append("Authentication bypass detected - payload granted unauthorized access")
        
        if redirect:
            reasons.append(f"Redirect response (302/301) - possible authentication bypass")
        
        if status_change:
            reasons.append("HTTP status code changed")
        
        if length_delta > 500:
            reasons.append(f"Significant response length change ({length_delta} bytes)")
        
        return ". ".join(reasons) if reasons else "Anomalous response detected"
