# modules/db_manager.py

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional
import os

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        # Ensure database directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.init_database()
        
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Assets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT,
                    ip TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    status TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    UNIQUE(name, type)
                )
            ''')
            
            # Ports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    port INTEGER,
                    service TEXT,
                    protocol TEXT,
                    last_scan TIMESTAMP,
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                )
            ''')
            
            # Technologies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS technologies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    tech_name TEXT,
                    tech_version TEXT,
                    detected_at TIMESTAMP,
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    cve_id TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    description TEXT,
                    discovered TIMESTAMP,
                    remediated TIMESTAMP,
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                )
            ''')
            
            # SSL Certificates table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ssl_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER,
                    issuer TEXT,
                    subject TEXT,
                    valid_from TIMESTAMP,
                    valid_to TIMESTAMP,
                    days_left INTEGER,
                    cipher_suite TEXT,
                    checked_at TIMESTAMP,
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                )
            ''')
            
            # Scan history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TIMESTAMP,
                    total_assets INTEGER,
                    live_assets INTEGER,
                    critical_risk INTEGER,
                    high_risk INTEGER,
                    medium_risk INTEGER,
                    low_risk INTEGER,
                    duration_seconds INTEGER
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    severity TEXT,
                    asset_name TEXT,
                    alert_type TEXT,
                    message TEXT,
                    acknowledged BOOLEAN DEFAULT 0
                )
            ''')
            
            conn.commit()
            
    def add_asset(self, name: str, asset_type: str, ip: Optional[str] = None, risk_score: int = 0, risk_level: str = 'LOW') -> int:
        """Add or update an asset"""
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO assets (name, type, ip, first_seen, last_seen, status, risk_score, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, type) DO UPDATE SET
                    last_seen = ?,
                    ip = COALESCE(?, ip),
                    risk_score = ?,
                    risk_level = ?,
                    status = ?
            ''', (name, asset_type, ip, now, now, 'active', risk_score, risk_level, now, ip, risk_score, risk_level, 'active'))
            
            conn.commit()
            cursor.execute('SELECT id FROM assets WHERE name = ? AND type = ?', (name, asset_type))
            result = cursor.fetchone()
            return result[0] if result else None
            
    def add_port(self, asset_id: int, port: int, service: str = '', protocol: str = 'tcp'):
        """Add open port for an asset"""
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO ports (asset_id, port, service, protocol, last_scan)
                VALUES (?, ?, ?, ?, ?)
            ''', (asset_id, port, service, protocol, now))
            
            conn.commit()
            
    def add_technology(self, asset_id: int, tech_name: str, tech_version: str = ''):
        """Add detected technology for an asset"""
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO technologies (asset_id, tech_name, tech_version, detected_at)
                VALUES (?, ?, ?, ?)
            ''', (asset_id, tech_name, tech_version, now))
            
            conn.commit()
            
    def add_vulnerability(self, asset_id: int, cve_id: str, severity: str, cvss_score: float, description: str):
        """Add vulnerability for an asset"""
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO vulnerabilities (asset_id, cve_id, severity, cvss_score, description, discovered)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (asset_id, cve_id, severity, cvss_score, description, now))
            
            conn.commit()
            
    def add_scan_history(self, total_assets: int, live_assets: int, critical: int, high: int, medium: int, low: int, duration: int):
        """Record scan history"""
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scan_history (scan_date, total_assets, live_assets, critical_risk, high_risk, medium_risk, low_risk, duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (now, total_assets, live_assets, critical, high, medium, low, duration))
            
            conn.commit()
            
    def add_alert(self, severity: str, asset_name: str, alert_type: str, message: str):
        """Add security alert"""
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (timestamp, severity, asset_name, alert_type, message)
                VALUES (?, ?, ?, ?, ?)
            ''', (now, severity, asset_name, alert_type, message))
            
            conn.commit()
            
    def get_assets(self, risk_level: str = None) -> List[Dict]:
        """Get all assets with their details"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = '''
                SELECT a.*, 
                       GROUP_CONCAT(DISTINCT p.port) as ports,
                       GROUP_CONCAT(DISTINCT t.tech_name) as technologies,
                       COUNT(DISTINCT v.id) as vuln_count
                FROM assets a
                LEFT JOIN ports p ON a.id = p.asset_id
                LEFT JOIN technologies t ON a.id = t.asset_id
                LEFT JOIN vulnerabilities v ON a.id = v.asset_id AND v.remediated IS NULL
                GROUP BY a.id
            '''
            
            if risk_level:
                query += f" HAVING a.risk_level = '{risk_level}'"
                
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]
            
    def get_alerts(self, acknowledged: bool = False) -> List[Dict]:
        """Get alerts"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE acknowledged = ?
                ORDER BY timestamp DESC
            ''', (acknowledged,))
            
            return [dict(row) for row in cursor.fetchall()]
            
    def get_statistics(self) -> Dict:
        """Get overall statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get asset counts by risk level
            cursor.execute('''
                SELECT risk_level, COUNT(*) 
                FROM assets 
                WHERE status = 'active'
                GROUP BY risk_level
            ''')
            risk_counts = dict(cursor.fetchall())
            
            # Get total port count
            cursor.execute('SELECT COUNT(DISTINCT port) FROM ports')
            total_ports = cursor.fetchone()[0] or 0
            
            # Get vulnerability count
            cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE remediated IS NULL')
            vuln_count = cursor.fetchone()[0] or 0
            
            return {
                'total_assets': len(self.get_assets()),
                'critical_assets': risk_counts.get('CRITICAL', 0),
                'high_assets': risk_counts.get('HIGH', 0),
                'medium_assets': risk_counts.get('MEDIUM', 0),
                'low_assets': risk_counts.get('LOW', 0),
                'total_ports': total_ports,
                'vulnerabilities': vuln_count
            }
            
    def get_recent_scans(self, limit: int = 30) -> List[Dict]:
        """Get recent scan history"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM scan_history 
                ORDER BY scan_date DESC 
                LIMIT ?
            ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
