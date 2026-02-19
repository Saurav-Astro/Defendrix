from core.http_client import fetch_url
from utils.helpers import inject_parameter


def scan_sqli(url):
    results = []
    
    baseline_response = fetch_url(url)
    if not baseline_response:
        return results
    
    baseline_length = len(baseline_response.text)
    
    payloads = [
        "' OR 1=1--",
        "'"
    ]
    
    error_keywords = [
        "SQL syntax",
        "mysql",
        "ODBC",
        "database error"
    ]
    
    for payload in payloads:
        injected_url = inject_parameter(url, payload)
        response = fetch_url(injected_url)
        
        if not response:
            continue
        
        response_text = response.text.lower()
        
        for keyword in error_keywords:
            if keyword.lower() in response_text:
                results.append({
                    "severity": "High",
                    "type": "SQL Injection",
                    "details": f"Potential SQL error detected with payload: {payload}"
                })
                return results
        
        if abs(len(response.text) - baseline_length) > 100:
            results.append({
                "severity": "Medium",
                "type": "SQL Injection",
                "details": f"Response length variation detected with payload: {payload}"
            })
    
    if not results:
        results.append({
            "severity": "Safe",
            "type": "SQL Injection",
            "details": "No SQL injection vulnerabilities detected"
        })
    
    return results
