# 🛡️ Defendrix
## Advanced Web Application Vulnerability Scanner

---

## 🚀 Overview

Defendrix is a modular Advanced Web Application Vulnerability Scanner designed to identify critical security weaknesses in modern web applications.

It dynamically discovers endpoints, maps the attack surface, and performs automated vulnerability testing aligned with OWASP Top 10 guidelines.

Built as a hackathon-focused MVP, Defendrix emphasizes modular architecture, stability, and practical security detection.

---

## 🎯 Core Features

### 🔍 Dynamic Endpoint Discovery
- Depth-limited crawling (configurable depth)
- Link extraction
- Form extraction
- Query parameter identification
- Input vector enumeration

### 🗺️ Attack Surface Mapping
- Total endpoints discovered
- Forms identified
- Parameters detected
- Input vectors counted
- Structured attack surface summary

### 🧪 OWASP-Aligned Vulnerability Detection

| Vulnerability Type | OWASP Category |
|--------------------|---------------|
| SQL Injection      | A03: Injection |
| Cross-Site Scripting (XSS) | A03: Injection |
| Server-Side Template Injection (SSTI) | A03: Injection |
| Security Misconfiguration | A05: Security Misconfiguration |

### 🔐 Detection Capabilities

- Error-based SQL Injection detection
- Boolean-based injection behavior analysis
- Reflected XSS detection
- Basic SSTI evaluation logic
- HTTP security header analysis

### 📊 Severity Classification

Each finding includes:
- Severity Level:
  - Critical
  - High
  - Medium
  - Low
  - Informational
- Confidence Score
- OWASP Category Mapping
- Endpoint Details
- Injected Payload
- Detailed Description

### 🌐 Passive Threat Intelligence

Defendrix integrates with the VirusTotal API (v3) to enrich findings with external threat intelligence data.

- URL reputation lookup
- Malicious / suspicious score extraction
- Contextual risk enrichment

API keys are handled securely via environment variables.

---

## 🏗️ Architecture Overview

Defendrix follows a modular layered architecture:

GUI Layer (PySide6)
        ↓
Scanner Engine (Orchestrator)
        ↓
Crawler & Attack Surface Mapper
        ↓
Vulnerability Modules
        ↓
Response Analyzer
        ↓
Severity Classifier
        ↓
Threat Intelligence Layer
        ↓
Result Aggregator
        ↓
Report Generator

The scanning engine is independent from the GUI for maintainability and scalability.

---

## ⚙️ Tech Stack

Language: Python 3.11+
GUI Framework: PySide6 (Qt for Python)
HTTP Handling: requests
HTML Parsing: BeautifulSoup
Concurrency: QThread
Threat Intelligence: VirusTotal API v3
Packaging: PyInstaller

---

## 📈 Scan Workflow

1. User enters target URL
2. Depth-limited crawling begins
3. Attack surface is mapped
4. Baseline response is captured
5. Payload-based vulnerability testing is executed
6. Response analysis is performed
7. Severity and confidence are assigned
8. Threat intelligence enrichment is applied
9. Structured findings are displayed
10. Detailed HTML report is generated

---

## 📄 Report Generation

Defendrix generates a structured HTML report containing:

- Target URL
- Scan timestamp
- Attack surface summary
- Detailed vulnerability findings
- Severity breakdown
- OWASP category mapping

Reports are formatted for professional presentation and review.

---

## 🔐 Security Considerations

- Session-based HTTP handling
- Safe timeout configuration
- Graceful exception handling
- No hardcoded API keys
- Controlled payload injection

---

## ⚠️ Scope & Limitations

This project is a hackathon MVP and intentionally scoped for stability.

Current limitations:

- No full JavaScript rendering engine
- No automated BOLA detection
- No OAST integration
- No distributed scanning
- Partial OWASP Top 10 coverage

The architecture supports modular expansion.

---


---

## 📦 Build Executable

pyinstaller --onefile --noconsole --collect-all PySide6 main.py

The executable will be available in the dist/ directory.

---

## 🚀 Future Enhancements

- JavaScript rendering engine integration
- Automated authentication workflow
- BOLA detection module
- Expanded OWASP Top 10 coverage
- Advanced reporting dashboard
- Enterprise API integration

---

## 🏁 Conclusion

Defendrix demonstrates how modular architecture, automated scanning, and threat intelligence enrichment can be combined to proactively identify vulnerabilities in web applications.

Security should not be reactive.
It should be proactive.

Defendrix aims to help detect vulnerabilities before attackers exploit them.
