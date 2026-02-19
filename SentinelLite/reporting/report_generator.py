from datetime import datetime


class ReportGenerator:
    def generate_html(self, file_path, target_url, surface, findings):
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        breakdown = self._severity_breakdown(findings)
        
        # Generate detailed findings sections
        critical_findings = [f for f in findings if f.get('severity') == 'Critical']
        high_findings = [f for f in findings if f.get('severity') == 'High']
        medium_findings = [f for f in findings if f.get('severity') == 'Medium']
        low_findings = [f for f in findings if f.get('severity') == 'Low']
        info_findings = [f for f in findings if f.get('severity') == 'Informational']
        
        # OWASP mapping
        owasp_categories = self._categorize_by_owasp(findings)
        
        html = self._generate_html_content(
            target_url, generated, surface, breakdown, 
            critical_findings, high_findings, medium_findings, low_findings, info_findings,
            owasp_categories, findings
        )
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _severity_breakdown(self, findings):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings:
            severity = f.get("severity", "Informational")
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _categorize_by_owasp(self, findings):
        categories = {}
        for f in findings:
            owasp = f.get('owasp_category', 'Uncategorized')
            if owasp not in categories:
                categories[owasp] = []
            categories[owasp].append(f)
        return categories

    def _get_owasp_description(self, category):
        descriptions = {
            "A01:2021 - Broken Access Control": "Restrictions on authenticated users are not properly enforced, allowing attackers to access unauthorized functionality or data.",
            "A02:2021 - Cryptographic Failures": "Failures related to cryptography which often leads to sensitive data exposure or system compromise.",
            "A03:2021 - Injection": "User-supplied data is not validated, filtered, or sanitized by the application, allowing injection attacks like SQL, XSS, or command injection.",
            "A04:2021 - Insecure Design": "Missing or ineffective control design, requiring secure design patterns and principles.",
            "A05:2021 - Security Misconfiguration": "Missing appropriate security hardening or improperly configured permissions on cloud services, databases, or web servers.",
            "A06:2021 - Vulnerable and Outdated Components": "Using components with known vulnerabilities or outdated versions.",
            "A07:2021 - Identification and Authentication Failures": "Confirmation of user identity, authentication, and session management is not properly implemented.",
            "A08:2021 - Software and Data Integrity Failures": "Code and infrastructure that does not protect against integrity violations.",
            "A09:2021 - Security Logging and Monitoring Failures": "Insufficient logging, detection, monitoring, and active response.",
            "A10:2021 - Server-Side Request Forgery (SSRF)": "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL."
        }
        return descriptions.get(category, "OWASP security vulnerability category.")

    def _get_remediation(self, finding_type):
        remediations = {
            "SQL Injection": {
                "description": "SQL Injection vulnerabilities allow attackers to interfere with database queries, potentially reading, modifying, or deleting data.",
                "impact": "Critical - Complete database compromise, data theft, data manipulation, authentication bypass.",
                "remediation": [
                    "Use parameterized queries (prepared statements) for all database interactions",
                    "Implement input validation and sanitization",
                    "Use ORM frameworks with built-in protection",
                    "Apply principle of least privilege to database accounts",
                    "Implement Web Application Firewall (WAF) rules",
                    "Regular security testing and code reviews"
                ],
                "references": [
                    "OWASP SQL Injection Prevention Cheat Sheet",
                    "CWE-89: SQL Injection",
                    "OWASP Top 10 A03:2021 - Injection"
                ]
            },
            "XSS": {
                "description": "Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users.",
                "impact": "High - Session hijacking, credential theft, malware distribution, website defacement.",
                "remediation": [
                    "Implement context-aware output encoding for all user input",
                    "Use Content Security Policy (CSP) headers",
                    "Sanitize HTML input using trusted libraries",
                    "Validate input on both client and server side",
                    "Use HTTPOnly and Secure flags on cookies",
                    "Implement XSS protection headers (X-XSS-Protection)"
                ],
                "references": [
                    "OWASP XSS Prevention Cheat Sheet",
                    "CWE-79: Cross-site Scripting",
                    "OWASP Top 10 A03:2021 - Injection"
                ]
            },
            "SSTI": {
                "description": "Server-Side Template Injection allows attackers to inject malicious code into templates, leading to RCE.",
                "impact": "Critical - Remote code execution, full server compromise, data exfiltration.",
                "remediation": [
                    "Avoid using user input in template expressions",
                    "Use logic-less template engines when possible",
                    "Implement strict input validation and sanitization",
                    "Use sandboxed template environments",
                    "Apply principle of least privilege",
                    "Regular security audits of template usage"
                ],
                "references": [
                    "OWASP Server-Side Template Injection",
                    "CWE-94: Code Injection",
                    "PortSwigger SSTI Research"
                ]
            },
            "Headers": {
                "description": "Missing security headers leave the application vulnerable to various attacks.",
                "impact": "Medium - Clickjacking, MIME sniffing attacks, protocol downgrade attacks.",
                "remediation": [
                    "Implement X-Frame-Options: DENY or SAMEORIGIN",
                    "Add Content-Security-Policy with strict directives",
                    "Set X-Content-Type-Options: nosniff",
                    "Enable Strict-Transport-Security (HSTS)",
                    "Add Referrer-Policy and Permissions-Policy headers",
                    "Regular header configuration audits"
                ],
                "references": [
                    "OWASP Secure Headers Project",
                    "CWE-16: Configuration",
                    "OWASP Top 10 A05:2021 - Security Misconfiguration"
                ]
            },
            "Threat Intelligence": {
                "description": "External threat intelligence indicates potential security risks associated with the target.",
                "impact": "Variable - Depends on threat severity and context.",
                "remediation": [
                    "Investigate flagged URLs and domains thoroughly",
                    "Review and validate all external dependencies",
                    "Implement regular threat intelligence monitoring",
                    "Apply security patches and updates promptly",
                    "Consider domain/URL reputation in security policies",
                    "Implement network-level blocking if necessary"
                ],
                "references": [
                    "OWASP Threat Modeling",
                    "NIST Cybersecurity Framework",
                    "MITRE ATT&CK Framework"
                ]
            }
        }
        return remediations.get(finding_type, {
            "description": "Security vulnerability identified.",
            "impact": "Requires assessment",
            "remediation": ["Review finding details", "Consult OWASP guidelines", "Implement security best practices"],
            "references": ["OWASP Top 10", "Security best practices documentation"]
        })

    def _generate_html_content(self, target_url, generated, surface, breakdown, 
                               critical, high, medium, low, info, owasp_categories, all_findings):
        
        executive_summary = self._generate_executive_summary(breakdown, surface)
        detailed_findings = self._generate_detailed_findings(critical, high, medium, low, info)
        owasp_section = self._generate_owasp_section(owasp_categories)
        
        endpoints = surface.get('endpoints', 0)
        parameters = surface.get('parameters', 0)
        forms = surface.get('forms', 0)
        input_vectors = surface.get('input_vectors', 0)
        total_findings = len(all_findings)
        
        # CSS as a separate string to avoid f-string interpretation issues
        css_styles = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f9fafb;
        }
        
        .container { 
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        
        .report-header {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 60px 40px;
            border-radius: 12px;
            margin-bottom: 40px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .report-header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .report-header .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
            margin-bottom: 30px;
        }
        
        .report-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        
        .meta-item {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
        }
        
        .meta-label {
            font-size: 0.85rem;
            opacity: 0.8;
            margin-bottom: 5px;
        }
        
        .meta-value {
            font-size: 1.1rem;
            font-weight: 600;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        }
        
        .card h2 {
            color: #1e293b;
            font-size: 1.8rem;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 3px solid #22c55e;
        }
        
        .card h3 {
            color: #334155;
            font-size: 1.3rem;
            margin-top: 25px;
            margin-bottom: 15px;
        }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }
        
        .severity-badge {
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            color: white;
            font-weight: 600;
        }
        
        .severity-critical { background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); }
        .severity-high { background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%); }
        .severity-medium { background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%); }
        .severity-low { background: linear-gradient(135deg, #ca8a04 0%, #eab308 100%); }
        .severity-info { background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%); }
        
        .severity-count {
            font-size: 2.5rem;
            display: block;
            margin-bottom: 5px;
        }
        
        .severity-label {
            font-size: 0.9rem;
            opacity: 0.95;
        }
        
        .surface-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }
        
        .surface-item {
            background: #f1f5f9;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #22c55e;
        }
        
        .surface-value {
            font-size: 2rem;
            font-weight: 700;
            color: #1e293b;
            display: block;
        }
        
        .surface-label {
            color: #64748b;
            font-size: 0.9rem;
            margin-top: 5px;
        }
        
        .finding {
            background: #f8fafc;
            border-left: 4px solid #94a3b8;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 8px;
        }
        
        .finding.critical { border-left-color: #7f1d1d; background: #fef2f2; }
        .finding.high { border-left-color: #dc2626; background: #fef2f2; }
        .finding.medium { border-left-color: #d97706; background: #fffbeb; }
        .finding.low { border-left-color: #ca8a04; background: #fefce8; }
        .finding.info { border-left-color: #2563eb; background: #eff6ff; }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }
        
        .finding-title {
            font-size: 1.2rem;
            font-weight: 700;
            color: #1e293b;
        }
        
        .finding-severity {
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 600;
            color: white;
        }
        
        .finding-details {
            margin-top: 15px;
        }
        
        .detail-row {
            margin-bottom: 12px;
        }
        
        .detail-label {
            font-weight: 600;
            color: #475569;
            display: inline-block;
            min-width: 120px;
        }
        
        .detail-value {
            color: #1e293b;
        }
        
        .code-block {
            background: #1e293b;
            color: #22c55e;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .remediation {
            background: #ecfdf5;
            border: 1px solid #10b981;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
        
        .remediation h4 {
            color: #065f46;
            margin-bottom: 12px;
            font-size: 1.1rem;
        }
        
        .remediation ul {
            margin-left: 20px;
            color: #064e3b;
        }
        
        .remediation li {
            margin-bottom: 8px;
        }
        
        .references {
            background: #eff6ff;
            border: 1px solid #3b82f6;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }
        
        .references h4 {
            color: #1e40af;
            margin-bottom: 10px;
            font-size: 1rem;
        }
        
        .references ul {
            margin-left: 20px;
            color: #1e3a8a;
        }
        
        .owasp-category {
            background: #fefce8;
            border: 2px solid #ca8a04;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .owasp-category h3 {
            color: #854d0e;
            margin-top: 0;
        }
        
        .owasp-description {
            color: #713f12;
            margin-bottom: 15px;
            font-style: italic;
        }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .findings-table th {
            background: #1e293b;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        .findings-table td {
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .findings-table tr:hover {
            background: #f9fafb;
        }
        
        .report-footer {
            margin-top: 50px;
            padding: 30px;
            background: #f1f5f9;
            border-radius: 12px;
            text-align: center;
            color: #64748b;
        }
        
        @media print {
            body { background: white; }
            .card { box-shadow: none; border: 1px solid #e5e7eb; }
            .report-header { background: #1e293b !important; }
        }
        """
        
        # Build HTML with dynamic content
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Defendrix Security Assessment Report - {target_url}</title>
    <style>
        {css_styles}
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>🛡️ Security Assessment Report</h1>
            <div class="subtitle">Comprehensive Web Application Security Analysis</div>
            
            <div class="report-meta">
                <div class="meta-item">
                    <div class="meta-label">Target Application</div>
                    <div class="meta-value">{target_url}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Report Generated</div>
                    <div class="meta-value">{generated}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scanner</div>
                    <div class="meta-value">Defendrix v1.0</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Total Findings</div>
                    <div class="meta-value">{total_findings}</div>
                </div>
            </div>
        </div>
        
        {executive_summary}
        
        <div class="card">
            <h2>📊 Attack Surface Analysis</h2>
            <p>The attack surface represents all possible entry points that could be exploited by an attacker. A larger attack surface increases the potential for vulnerabilities.</p>
            
            <div class="surface-grid">
                <div class="surface-item">
                    <span class="surface-value">{endpoints}</span>
                    <div class="surface-label">Endpoints Discovered</div>
                </div>
                <div class="surface-item">
                    <span class="surface-value">{parameters}</span>
                    <div class="surface-label">Parameters Identified</div>
                </div>
                <div class="surface-item">
                    <span class="surface-value">{forms}</span>
                    <div class="surface-label">Forms Detected</div>
                </div>
                <div class="surface-item">
                    <span class="surface-value">{input_vectors}</span>
                    <div class="surface-label">Input Vectors Found</div>
                </div>
            </div>
        </div>
        
        {owasp_section}
        
        {detailed_findings}
        
        <div class="report-footer">
            <p><strong>Generated by Defendrix</strong> - Advanced Web Application Security Scanner</p>
            <p>This report follows OWASP Testing Guide v4.2 methodology and OWASP Top 10 2021 classifications</p>
            <p style="margin-top: 15px; font-size: 0.9rem;">
                For questions or support, consult OWASP documentation at <a href="https://owasp.org" style="color: #2563eb;">owasp.org</a>
            </p>
        </div>
    </div>
</body>
</html>"""
        
        return html

    def _generate_executive_summary(self, breakdown, surface):
        total = sum(breakdown.values())
        risk_level = "CRITICAL" if breakdown['Critical'] > 0 else "HIGH" if breakdown['High'] > 0 else "MEDIUM" if breakdown['Medium'] > 0 else "LOW"
        
        critical_warning = ""
        if breakdown['Critical'] + breakdown['High'] > 0:
            critical_warning = "<li style='color: #dc2626; font-weight: 600;'>Address Critical and High severity findings immediately</li>"
        
        return f"""
        <div class="card">
            <h2>📋 Executive Summary</h2>
            <p style="font-size: 1.1rem; margin-bottom: 25px;">
                This security assessment identified <strong>{total} security findings</strong> across the target application. 
                The overall risk level is classified as <strong style="color: #dc2626;">{risk_level}</strong>.
            </p>
            
            <h3>Severity Distribution</h3>
            <div class="severity-grid">
                <div class="severity-badge severity-critical">
                    <span class="severity-count">{breakdown['Critical']}</span>
                    <span class="severity-label">Critical</span>
                </div>
                <div class="severity-badge severity-high">
                    <span class="severity-count">{breakdown['High']}</span>
                    <span class="severity-label">High</span>
                </div>
                <div class="severity-badge severity-medium">
                    <span class="severity-count">{breakdown['Medium']}</span>
                    <span class="severity-label">Medium</span>
                </div>
                <div class="severity-badge severity-low">
                    <span class="severity-count">{breakdown['Low']}</span>
                    <span class="severity-label">Low</span>
                </div>
                <div class="severity-badge severity-info">
                    <span class="severity-count">{breakdown['Informational']}</span>
                    <span class="severity-label">Informational</span>
                </div>
            </div>
            
            <h3>Key Recommendations</h3>
            <ul style="margin-left: 25px; margin-top: 15px;">
                {critical_warning}
                <li>Implement input validation and output encoding across all user inputs</li>
                <li>Configure security headers according to OWASP recommendations</li>
                <li>Conduct regular security assessments and penetration testing</li>
                <li>Implement a Web Application Firewall (WAF)</li>
                <li>Train development team on secure coding practices</li>
            </ul>
        </div>
        """

    def _generate_owasp_section(self, owasp_categories):
        if not owasp_categories:
            return ""
        
        category_html = []
        for category, findings in sorted(owasp_categories.items()):
            description = self._get_owasp_description(category)
            finding_count = len(findings)
            
            finding_list = "<ul style='margin-left: 20px;'>"
            for f in findings[:5]:
                finding_list += f"<li>{f.get('type')} - {f.get('severity')} severity at {f.get('endpoint')}</li>"
            if finding_count > 5:
                finding_list += f"<li><em>...and {finding_count - 5} more findings</em></li>"
            finding_list += "</ul>"
            
            category_html.append(f"""
                <div class="owasp-category">
                    <h3>{category}</h3>
                    <div class="owasp-description">{description}</div>
                    <div><strong>Findings Count:</strong> {finding_count}</div>
                    {finding_list}
                </div>
            """)
        
        return f"""
        <div class="card">
            <h2>🎯 OWASP Top 10 2021 Mapping</h2>
            <p>Findings categorized according to the OWASP Top 10 2021 security risk classification framework.</p>
            {''.join(category_html)}
        </div>
        """

    def _generate_detailed_findings(self, critical, high, medium, low, info):
        sections = []
        
        if critical:
            sections.append(self._generate_severity_section("Critical", critical, "critical"))
        if high:
            sections.append(self._generate_severity_section("High", high, "high"))
        if medium:
            sections.append(self._generate_severity_section("Medium", medium, "medium"))
        if low:
            sections.append(self._generate_severity_section("Low", low, "low"))
        if info:
            sections.append(self._generate_severity_section("Informational", info, "info"))
        
        return ''.join(sections)

    def _generate_severity_section(self, severity, findings, css_class):
        severity_colors = {
            "Critical": "#7f1d1d",
            "High": "#dc2626",
            "Medium": "#d97706",
            "Low": "#ca8a04",
            "Informational": "#2563eb"
        }
        
        findings_html = []
        for f in findings:
            remediation_info = self._get_remediation(f.get('type'))
            
            payload_html = ""
            if f.get('payload'):
                payload_html = f"""
                <div class="detail-row">
                    <span class="detail-label">Test Payload:</span>
                    <div class="code-block">{f.get('payload')}</div>
                </div>
                """
            
            remediation_steps = ''.join([f"<li>{step}</li>" for step in remediation_info.get('remediation', [])])
            references = ''.join([f"<li>{ref}</li>" for ref in remediation_info.get('references', [])])
            
            findings_html.append(f"""
                <div class="finding {css_class}">
                    <div class="finding-header">
                        <div class="finding-title">🔍 {f.get('type')}</div>
                        <div class="finding-severity" style="background: {severity_colors[severity]};">{severity}</div>
                    </div>
                    
                    <div class="finding-details">
                        <div class="detail-row">
                            <span class="detail-label">OWASP Category:</span>
                            <span class="detail-value">{f.get('owasp_category')}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Confidence:</span>
                            <span class="detail-value">{f.get('confidence')}%</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Affected Endpoint:</span>
                            <span class="detail-value">{f.get('endpoint')}</span>
                        </div>
                        {payload_html}
                        <div class="detail-row">
                            <span class="detail-label">Description:</span>
                            <div class="detail-value" style="margin-top: 8px;">{f.get('details')}</div>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Detection Source:</span>
                            <span class="detail-value">{f.get('source')}</span>
                        </div>
                    </div>
                    
                    <div class="remediation">
                        <h4>💡 Vulnerability Details</h4>
                        <p><strong>Impact:</strong> {remediation_info.get('impact', 'N/A')}</p>
                        <p style="margin-top: 10px;">{remediation_info.get('description', '')}</p>
                        
                        <h4 style="margin-top: 20px;">🔧 Remediation Steps</h4>
                        <ul>
                            {remediation_steps}
                        </ul>
                    </div>
                    
                    <div class="references">
                        <h4>📚 References & Resources</h4>
                        <ul>
                            {references}
                        </ul>
                    </div>
                </div>
            """)
        
        return f"""
        <div class="card">
            <h2 style="border-bottom-color: {severity_colors[severity]};">
                {severity} Severity Findings ({len(findings)})
            </h2>
            {''.join(findings_html)}
        </div>
        """
