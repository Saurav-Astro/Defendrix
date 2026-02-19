import base64
import os
import requests

from SentinelLite.engine.severity_classifier import SeverityClassifier
from SentinelLite.models.finding import Finding


class VirusTotalClient:
    def __init__(self, api_key=None, timeout=5):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.timeout = timeout
        self.classifier = SeverityClassifier()

    def check_url_reputation(self, url):
        if not self.api_key:
            return None

        try:
            url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=self.timeout,
            )
            
            if response.status_code != 200:
                return None

            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            
            severity, confidence = self.classifier.threat(malicious, suspicious)
            
            if malicious + suspicious > 0:
                detail = (
                    f"External Threat Intelligence: {malicious} security vendors flagged this URL as malicious, "
                    f"{suspicious} flagged as suspicious. "
                    f"Total scanners: {malicious + suspicious + harmless + undetected}. "
                    f"⚠️ This URL may pose a security risk."
                )
            else:
                detail = (
                    f"External Threat Intelligence: URL appears clean. "
                    f"Scanned by {harmless + undetected} security vendors with no malicious detections."
                )

            return Finding(
                type="Threat Intelligence",
                owasp_category="A08: Software and Data Integrity Failures",
                severity=severity,
                confidence=confidence,
                endpoint=url,
                payload=None,
                details=detail,
                source="ThreatIntel",
            ).to_dict()
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            return None

        return None
