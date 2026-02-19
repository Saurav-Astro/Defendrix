class SeverityClassifier:
    def sqli(self, analysis, threshold):
        if analysis.get("auth_bypass"):
            return "Critical", "High"
        
        if analysis.get("sql_error"):
            return "High", "High"
        
        if analysis.get("length_delta", 0) > threshold:
            return "Medium", "Medium"
        
        if analysis.get("status_change"):
            return "Low", "Low"
        
        return None, None

    def xss(self, analysis):
        if analysis.get("reflected"):
            return "High", "Medium"
        return None, None

    def ssti(self, analysis):
        if analysis.get("ssti_eval"):
            return "High", "High"
        return None, None

    def headers(self, missing):
        if missing:
            return "Medium", "High"
        return None, None

    def threat(self, malicious, suspicious):
        score = malicious + suspicious
        if score >= 5:
            return "Medium", "High"
        if score > 0:
            return "Informational", "Low"
        return "Informational", "Low"
