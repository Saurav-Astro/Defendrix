from datetime import datetime


class ReportGenerator:
    def __init__(self, scan_data, vulnerabilities):
        self.scan_data = scan_data
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.now()
    
    def generate_text_report(self):
        report = self._build_text_report()
        return report
    
    def generate_html_report(self):
        report = self._build_html_report()
        return report
    
    def _build_text_report(self):
        lines = []
        lines.append("=" * 100)
        lines.append("DEFENDRIX - PROFESSIONAL VULNERABILITY SCAN REPORT".center(100))
        lines.append("=" * 100)
        lines.append("")
        
        lines.append(f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Target URL: {self.scan_data.get('url', 'N/A')}")
        lines.append(f"Scan Date: {self.scan_data.get('scan_date', 'N/A')}")
        lines.append(f"Scan Time: {self.scan_data.get('scan_time', 'N/A')}")
        lines.append("")
        
        lines.append("-" * 100)
        lines.append("EXECUTIVE SUMMARY".ljust(100))
        lines.append("-" * 100)
        lines.append(f"Overall Status: {self.scan_data.get('overall_status', 'UNKNOWN')}".ljust(100))
        lines.append(f"Security Score: {self.scan_data.get('security_score', 0)}%".ljust(100))
        lines.append(f"Total Vulnerabilities Found: {self.scan_data.get('total_vulnerabilities', 0)}".ljust(100))
        lines.append("")
        
        lines.append("-" * 100)
        lines.append("VULNERABILITY STATISTICS".ljust(100))
        lines.append("-" * 100)
        lines.append(f"High Severity Issues: {self.scan_data.get('high_severity', 0)}".ljust(100))
        lines.append(f"Medium Severity Issues: {self.scan_data.get('medium_severity', 0)}".ljust(100))
        lines.append(f"Safe/No Issues: {self.scan_data.get('safe_issues', 0)}".ljust(100))
        lines.append("")
        
        if self.vulnerabilities:
            lines.append("-" * 100)
            lines.append("DETAILED FINDINGS".ljust(100))
            lines.append("-" * 100)
            lines.append("")
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                severity = vuln.get('severity', 'Unknown')
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                details = vuln.get('details', 'N/A')
                
                lines.append(f"Finding #{idx}: {vuln_type}")
                lines.append(f"Severity: {severity}")
                lines.append(f"Details: {details}")
                lines.append("")
        
        lines.append("=" * 100)
        lines.append("END OF REPORT".center(100))
        lines.append("=" * 100)
        
        return "\n".join(lines)
    
    def _build_html_report(self):
        severity_colors = {
            'High': '#e74c3c',
            'Medium': '#f39c12',
            'Safe': '#27ae60'
        }
        
        high_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'High')
        medium_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Medium')
        safe_count = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Safe')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Defendrix Vulnerability Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background-color: #f5f7fa;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 1000px;
                    margin: 0 auto;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    padding: 40px;
                }}
                .header {{
                    border-bottom: 3px solid #1e3a5f;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    color: #1e3a5f;
                    margin: 0;
                    font-size: 28px;
                }}
                .header p {{
                    color: #666;
                    margin: 5px 0;
                }}
                .info-grid {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .info-item {{
                    padding: 15px;
                    background-color: #f9f9f9;
                    border-left: 4px solid #00d4ff;
                    border-radius: 4px;
                }}
                .info-item label {{
                    font-weight: bold;
                    color: #1e3a5f;
                    display: block;
                    margin-bottom: 5px;
                }}
                .info-item value {{
                    color: #333;
                    font-size: 16px;
                }}
                .summary {{
                    background: linear-gradient(135deg, #1e3a5f 0%, #2c5aa0 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                    text-align: center;
                }}
                .summary h2 {{
                    margin-top: 0;
                    font-size: 24px;
                }}
                .summary-stat {{
                    display: inline-block;
                    margin: 0 30px;
                    text-align: center;
                }}
                .summary-stat .number {{
                    font-size: 32px;
                    font-weight: bold;
                }}
                .summary-stat .label {{
                    font-size: 12px;
                    opacity: 0.9;
                }}
                .statistics {{
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 15px;
                    margin-bottom: 30px;
                }}
                .stat-card {{
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    color: white;
                }}
                .stat-card.high {{
                    background-color: #e74c3c;
                }}
                .stat-card.medium {{
                    background-color: #f39c12;
                }}
                .stat-card.safe {{
                    background-color: #27ae60;
                }}
                .stat-card .number {{
                    font-size: 32px;
                    font-weight: bold;
                    margin: 0;
                }}
                .stat-card .label {{
                    font-size: 12px;
                    margin: 5px 0 0 0;
                    opacity: 0.9;
                }}
                .findings {{
                    margin-top: 30px;
                }}
                .findings h3 {{
                    color: #1e3a5f;
                    border-bottom: 2px solid #00d4ff;
                    padding-bottom: 10px;
                }}
                .finding-item {{
                    margin-bottom: 20px;
                    padding: 20px;
                    border-left: 4px solid #ddd;
                    background-color: #f9f9f9;
                    border-radius: 4px;
                }}
                .finding-item.high {{
                    border-left-color: #e74c3c;
                    background-color: #fdf5f5;
                }}
                .finding-item.medium {{
                    border-left-color: #f39c12;
                    background-color: #fffbf5;
                }}
                .finding-item.safe {{
                    border-left-color: #27ae60;
                    background-color: #f5fdf9;
                }}
                .finding-severity {{
                    display: inline-block;
                    padding: 5px 10px;
                    border-radius: 4px;
                    color: white;
                    font-weight: bold;
                    font-size: 12px;
                    margin-right: 10px;
                }}
                .finding-severity.high {{
                    background-color: #e74c3c;
                }}
                .finding-severity.medium {{
                    background-color: #f39c12;
                }}
                .finding-severity.safe {{
                    background-color: #27ae60;
                }}
                .finding-type {{
                    font-size: 16px;
                    font-weight: bold;
                    color: #333;
                    margin: 10px 0;
                }}
                .finding-details {{
                    color: #666;
                    margin: 10px 0;
                    padding: 10px;
                    background-color: white;
                    border-radius: 4px;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    color: #999;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Defendrix - Vulnerability Assessment Report</h1>
                    <p>Professional Security Scanning & Analysis</p>
                </div>
                
                <div class="info-grid">
                    <div class="info-item">
                        <label>Target URL</label>
                        <value>{self.scan_data.get('url', 'N/A')}</value>
                    </div>
                    <div class="info-item">
                        <label>Scan Date & Time</label>
                        <value>{self.scan_data.get('scan_date')} {self.scan_data.get('scan_time')}</value>
                    </div>
                    <div class="info-item">
                        <label>Report Generated</label>
                        <value>{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</value>
                    </div>
                    <div class="info-item">
                        <label>Overall Status</label>
                        <value style="color: {'#e74c3c' if self.scan_data.get('overall_status') == 'CRITICAL' else '#f39c12' if self.scan_data.get('overall_status') == 'WARNING' else '#27ae60'};">
                            {self.scan_data.get('overall_status', 'UNKNOWN')}
                        </value>
                    </div>
                </div>
                
                <div class="summary">
                    <h2>Security Assessment Summary</h2>
                    <div class="summary-stat">
                        <div class="number">{self.scan_data.get('security_score', 0)}%</div>
                        <div class="label">Security Score</div>
                    </div>
                    <div class="summary-stat">
                        <div class="number">{self.scan_data.get('total_vulnerabilities', 0)}</div>
                        <div class="label">Total Issues Found</div>
                    </div>
                </div>
                
                <div class="statistics">
                    <div class="stat-card high">
                        <div class="number">{self.scan_data.get('high_severity', 0)}</div>
                        <div class="label">HIGH SEVERITY</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="number">{self.scan_data.get('medium_severity', 0)}</div>
                        <div class="label">MEDIUM SEVERITY</div>
                    </div>
                    <div class="stat-card safe">
                        <div class="number">{self.scan_data.get('safe_issues', 0)}</div>
                        <div class="label">SAFE</div>
                    </div>
                </div>
                
                <div class="findings">
                    <h3>📋 Detailed Findings</h3>
        """
        
        if not self.vulnerabilities:
            html += """
                    <div class="finding-item safe">
                        <p style="margin: 0; color: #27ae60; font-weight: bold;">No vulnerabilities detected</p>
                    </div>
            """
        else:
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                severity = vuln.get('severity', 'Unknown').lower()
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                details = vuln.get('details', 'N/A')
                
                html += f"""
                    <div class="finding-item {severity}">
                        <span class="finding-severity {severity}">{vuln.get('severity', 'Unknown')}</span>
                        <span style="font-weight: bold; color: #333;">Finding #{idx}</span>
                        <div class="finding-type">{vuln_type}</div>
                        <div class="finding-details">{details}</div>
                    </div>
                """
        
        html += """
                </div>
                
                <div class="footer">
                    <p>This report was generated by Defendrix - Professional Web Vulnerability Scanner</p>
                    <p>© 2024 Defendrix. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
