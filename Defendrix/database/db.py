import sqlite3
from datetime import datetime
import os
import hashlib


class DefendrixDatabase:
    def __init__(self, db_path="defendrix_data.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                total_vulnerabilities INTEGER,
                high_severity INTEGER,
                medium_severity INTEGER,
                safe_issues INTEGER,
                security_score REAL,
                overall_status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                report_name TEXT NOT NULL,
                report_content TEXT NOT NULL,
                generated_date TEXT NOT NULL,
                file_path TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question_type TEXT UNIQUE NOT NULL,
                answer_hash TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def set_admin_password(self, password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        password_hash = self.hash_password(password)
        
        cursor.execute('DELETE FROM security_settings WHERE setting_key = ?', ('admin_password',))
        cursor.execute('''
            INSERT INTO security_settings (setting_key, setting_value)
            VALUES (?, ?)
        ''', ('admin_password', password_hash))
        
        conn.commit()
        conn.close()
    
    def get_admin_password(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT setting_value FROM security_settings WHERE setting_key = ?', ('admin_password',))
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None
    
    def verify_admin_password(self, password):
        stored_hash = self.get_admin_password()
        if not stored_hash:
            return False
        
        return self.hash_password(password) == stored_hash
    
    def set_security_question(self, question_type, answer):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        answer_hash = self.hash_password(answer.lower().strip())
        
        cursor.execute('DELETE FROM security_questions WHERE question_type = ?', (question_type,))
        cursor.execute('''
            INSERT INTO security_questions (question_type, answer_hash)
            VALUES (?, ?)
        ''', (question_type, answer_hash))
        
        conn.commit()
        conn.close()
    
    def verify_security_question(self, question_type, answer):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT answer_hash FROM security_questions WHERE question_type = ?', (question_type,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False
        
        answer_hash = self.hash_password(answer.lower().strip())
        return result[0] == answer_hash
    
    def has_security_questions(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM security_questions')
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0
    
    def save_scan(self, url, vulnerabilities):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.now()
        scan_date = now.strftime("%Y-%m-%d")
        scan_time = now.strftime("%H:%M:%S")
        
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
        medium_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Medium')
        safe_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Safe')
        total_count = len(vulnerabilities)
        
        if total_count > 0:
            security_score = round((safe_count / total_count) * 100, 2)
        else:
            security_score = 100.0
        
        if high_count > 0:
            overall_status = "CRITICAL"
        elif medium_count > 0:
            overall_status = "WARNING"
        else:
            overall_status = "SAFE"
        
        cursor.execute('''
            INSERT INTO scans (url, scan_date, scan_time, total_vulnerabilities, 
                              high_severity, medium_severity, safe_issues, 
                              security_score, overall_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (url, scan_date, scan_time, total_count, high_count, medium_count, 
              safe_count, security_score, overall_status))
        
        scan_id = cursor.lastrowid
        
        for vuln in vulnerabilities:
            cursor.execute('''
                INSERT INTO vulnerabilities (scan_id, vulnerability_type, severity, 
                                            details, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_id, vuln.get('type'), vuln.get('severity'), 
                  vuln.get('details'), datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return scan_id
    
    def get_all_scans(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scans ORDER BY scan_date DESC, scan_time DESC
        ''')
        
        scans = cursor.fetchall()
        conn.close()
        
        return [dict(scan) for scan in scans]
    
    def get_scan_by_id(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()
        
        if scan:
            cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            vulnerabilities = cursor.fetchall()
            conn.close()
            return dict(scan), [dict(v) for v in vulnerabilities]
        
        conn.close()
        return None, []
    
    def get_vulnerabilities_by_scan(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
        vulns = cursor.fetchall()
        conn.close()
        
        return [dict(v) for v in vulns]
    
    def save_report(self, scan_id, report_name, report_content, file_path=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO reports (scan_id, report_name, report_content, generated_date, file_path)
            VALUES (?, ?, ?, ?, ?)
        ''', (scan_id, report_name, report_content, datetime.now().isoformat(), file_path))
        
        report_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return report_id
    
    def get_reports_by_scan(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM reports WHERE scan_id = ?', (scan_id,))
        reports = cursor.fetchall()
        conn.close()
        
        return [dict(r) for r in reports]
    
    def get_statistics(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT SUM(total_vulnerabilities) FROM scans')
        total_vulns = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT SUM(high_severity) FROM scans')
        total_high = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT AVG(security_score) FROM scans')
        avg_score = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulns,
            'total_high_severity': total_high,
            'average_security_score': round(avg_score, 2)
        }
