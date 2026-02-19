from core.http_client import fetch_url


def scan_headers(url):
    results = []
    
    response = fetch_url(url)
    
    if not response:
        results.append({
            "severity": "Medium",
            "type": "Headers",
            "details": "Could not retrieve response headers"
        })
        return results
    
    headers = response.headers
    
    required_headers = {
        "X-Frame-Options": "Prevents clickjacking attacks",
        "Content-Security-Policy": "Prevents injection attacks",
        "X-Content-Type-Options": "Prevents MIME-type sniffing",
        "Strict-Transport-Security": "Enforces HTTPS connections"
    }
    
    missing_headers = []
    
    for header, description in required_headers.items():
        if header not in headers:
            missing_headers.append(header)
    
    if missing_headers:
        results.append({
            "severity": "Medium",
            "type": "Headers",
            "details": f"Missing security headers: {', '.join(missing_headers)}"
        })
    else:
        results.append({
            "severity": "Safe",
            "type": "Headers",
            "details": "All required security headers are present"
        })
    
    return results
