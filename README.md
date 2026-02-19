# 🛡️ Defendrix
## Modular Web Application Vulnerability Assessment Framework

---

## 🚀 Overview

Defendrix is a modular web application vulnerability assessment framework designed to identify critical security weaknesses in modern web applications.

It dynamically discovers endpoints, maps the attack surface, and performs automated vulnerability testing aligned with key OWASP security standards.

Built as a structured and extensible MVP, Defendrix emphasizes:

- Clean modular architecture
- Controlled payload execution
- Detection confidence scoring
- Stable, depth-limited scanning
- Professional report generation

The system is designed to proactively identify vulnerabilities before exploitation.

---

## 🎯 Core Capabilities

### 🔍 Dynamic Endpoint Discovery
- Depth-controlled crawling
- Link extraction
- Form detection
- Query parameter identification
- Input vector enumeration
- Duplicate endpoint prevention

### 🗺️ Attack Surface Mapping
- Total endpoints discovered
- Total forms identified
- Total parameters extracted
- Input vector aggregation
- Structured surface summary dashboard

### 🧪 OWASP-Aligned Vulnerability Detection

| Vulnerability Type | OWASP Category Alignment |
|--------------------|--------------------------|
| SQL Injection      | A03: Injection |
| Cross-Site Scripting (XSS) | A03: Injection |
| Server-Side Template Injection (SSTI) | A03: Injection |
| Security Misconfiguration | A05: Security Misconfiguration |

---

## 🔐 Detection Methodology

Defendrix uses a structured detection strategy:

- Baseline vs mutated response comparison
- Structured payload mutation engine
- Behavioral response analysis
- Error pattern identification
- Response length delta evaluation
- Payload reflection validation
- Multi-mutation confirmation for confidence scoring

This approach reduces false positives while improving detection reliability.

---

## 📊 Severity & Confidence Model

Each finding includes:

- Severity Classification  
  - Critical  
  - High  
  - Medium  
  - Low  
  - Informational  

- Confidence Score  
  - High  
  - Medium  
  - Low  

- OWASP Category Mapping  
- Affected Endpoint  
- Triggered Payload  
- Detailed Explanation  

Severity represents risk impact.  
Confidence represents detection reliability.

---

## 🌐 Threat Intelligence Enrichment

Defendrix incorporates external threat intelligence enrichment to provide contextual risk insights.

- URL reputation evaluation
- Context-based risk tagging
- Passive enrichment integration

API credentials are securely managed via environment variables.

---

## 🏗️ Architecture Overview

Defendrix follows a modular layered architecture:

GUI Layer (PySide6)
        ↓
Scanner Engine (Orchestrator)
        ↓
Crawler & Attack Surface Mapper
        ↓
Mutation Engine
        ↓
Vulnerability Modules
        ↓
Response Analyzer
        ↓
Severity & Confidence Classifier
        ↓
Threat Intelligence Layer
        ↓
Result Aggregator
        ↓
Report Generator

The scanning engine is fully independent from the user interface, ensuring maintainability and scalability.

---

## ⚙️ Technology Stack

Language: Python 3.11+
GUI Framework: PySide6 (Qt for Python)
HTTP Handling: requests
HTML Parsing: BeautifulSoup
Concurrency: QThread
Packaging: PyInstaller

---

## 📈 Scan Workflow

1. User enters target URL
2. Depth-limited crawling begins
3. Attack surface is mapped
4. Baseline response is captured
5. Structured payload mutation is generated
6. Parameter-isolated injection testing is executed
7. Response behavior is analyzed
8. Severity and confidence are assigned
9. Threat intelligence enrichment is applied
10. Structured findings are displayed
11. Detailed HTML report is generated

---

## 📄 Professional Report Generation

Defendrix generates structured HTML reports containing:

- Target Information
- Scan Timestamp
- Attack Surface Summary
- Detailed Vulnerability Findings
- Severity Distribution
- OWASP Category Alignment
- Confidence Levels

Reports are formatted for professional review and presentation.

---

## 🔐 Security Design Principles

- Session-based HTTP handling
- Timeout-controlled requests
- Controlled depth crawling
- Adaptive mutation stopping
- Parameter-isolated injection
- Secure environment-based configuration
- No hardcoded secrets

---

## ⚠️ Scope & Limitations

Defendrix is intentionally scoped as a controlled MVP.

Current limitations include:

- No full JavaScript rendering engine
- No automated BOLA detection
- No OAST-based vulnerability validation
- No distributed scanning infrastructure
- Partial OWASP Top 10 coverage

The architecture supports modular expansion for future development.

---

## 📦 Build Executable

pyinstaller --onefile --noconsole --collect-all PySide6 main.py

The compiled executable will be available inside the dist/ directory.

---

## 🚀 Future Enhancements

- JavaScript-aware crawling
- Automated authentication workflows
- Access control testing modules
- Extended OWASP Top 10 coverage
- CI/CD integration
- Enterprise scanning mode
- Advanced performance analytics

---

## 🏁 Conclusion

Defendrix demonstrates how modular design, structured mutation-based testing, and behavioral response analysis can be combined to proactively identify web application vulnerabilities.

Security should not be reactive.

It should be engineered.

Defendrix is built to detect vulnerabilities before attackers do.
