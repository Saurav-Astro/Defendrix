from SentinelLite.models.finding import Finding
from SentinelLite.engine.severity_classifier import SeverityClassifier


class HeaderModule:
    def __init__(self, required_headers):
        self.required_headers = required_headers
        self.classifier = SeverityClassifier()

    def run(self, url, request_manager):
        findings = []
        response = request_manager.get(url)
        if not response:
            return findings

        missing_headers = [header for header in self.required_headers if header not in response.headers]
        severity, confidence = self.classifier.headers(missing_headers)
        if severity:
            findings.append(
                Finding(
                    type="Security Headers",
                    owasp_category="A05: Security Misconfiguration",
                    severity=severity,
                    confidence=confidence,
                    endpoint=url,
                    payload=None,
                    details=f"Missing security headers: {', '.join(missing_headers)}.",
                    source="ActiveScan",
                ).to_dict()
            )

        return findings
