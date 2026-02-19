from core.http_client import fetch_url
from utils.helpers import inject_parameter


def scan_xss(url):
    results = []
    
    payload = "<svg/onload=alert(1)>"
    injected_url = inject_parameter(url, payload)
    
    response = fetch_url(injected_url)
    
    if not response:
        results.append({
            "severity": "Safe",
            "type": "XSS",
            "details": "Could not test for XSS vulnerabilities"
        })
        return results
    
    if payload in response.text:
        results.append({
            "severity": "High",
            "type": "XSS",
            "details": f"Reflected XSS vulnerability detected - payload found unencoded in response"
        })
    else:
        results.append({
            "severity": "Safe",
            "type": "XSS",
            "details": "No XSS vulnerabilities detected"
        })
    
    return results
