import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
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
                    last_scan TIMESTAMP,
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
                    description TEXT,
                    discovered TIMESTAMP,
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                )
            ''')
            
            # Scan history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TIMESTAMP,
                    total_assets INTEGER,
                    critical_risk INTEGER,
                    high_risk INTEGER,
                    medium_risk INTEGER,
                    low_risk INTEGER
                )
            ''')
            
            conn.commit()
            
    def add_asset(self, name: str, asset_type: str, ip: Optional[str] = None) -> int:
        """Add or update an asset"""
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO assets (name, type, ip, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name, type) DO UPDATE SET
                    last_seen = ?,
                    ip = COALESCE(?, ip)
            ''', (name, asset_type, ip, now, now, 'active', now, ip))
            
            conn.commit()
            return cursor.lastrowid
            
    def add_port(self, asset_id: int, port: int, service: str = ''):
        """Add open port for an asset"""
        now = datetime.now()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO ports (asset_id, port, service, last_scan)
                VALUES (?, ?, ?, ?)
            ''', (asset_id, port, service, now))
            
            conn.commit()
            
    def get_assets(self) -> List[Dict]:
        """Get all assets with their details"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT a.*, GROUP_CONCAT(p.port) as ports
                FROM assets a
                LEFT JOIN ports p ON a.id = p.asset_id
                GROUP BY a.id
            ''')
            
            return [dict(row) for row in cursor.fetchall()]
