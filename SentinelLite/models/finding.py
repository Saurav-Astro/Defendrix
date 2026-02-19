from dataclasses import dataclass, field
import uuid
from typing import Optional


@dataclass
class Finding:
    type: str
    owasp_category: str
    severity: str
    confidence: str
    endpoint: str
    payload: Optional[str]
    details: str
    source: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self):
        return {
            "type": self.type,
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "confidence": self.confidence,
            "endpoint": self.endpoint,
            "payload": self.payload,
            "details": self.details,
            "source": self.source,
        }
