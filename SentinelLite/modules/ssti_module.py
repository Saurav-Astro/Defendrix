from SentinelLite.models.finding import Finding
from SentinelLite.engine.severity_classifier import SeverityClassifier


class SSTIModule:
    def __init__(self, payloads):
        self.payloads = payloads
        self.classifier = SeverityClassifier()

    def run(self, url, request_manager, mutation_engine, analyzer):
        findings = []
        baseline = request_manager.get(url)
        if not baseline:
            return findings

        for mutation in mutation_engine.generate_mutations(url, self.payloads):
            response = request_manager.get(mutation["url"])
            if not response:
                continue

            analysis = analyzer.analyze(baseline, response, mutation["payload"])
            severity, confidence = self.classifier.ssti(analysis)
            if severity:
                findings.append(
                    Finding(
                        type="SSTI",
                        owasp_category="A03: Injection",
                        severity=severity,
                        confidence=confidence,
                        endpoint=url,
                        payload=mutation["payload"],
                        details="SSTI payload evaluated in response.",
                        source="ActiveScan",
                    ).to_dict()
                )

        return findings
