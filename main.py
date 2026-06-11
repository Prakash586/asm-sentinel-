#!/usr/bin/env python3

import yaml
import time
import schedule
import argparse
from datetime import datetime
from modules import *
from modules.db_manager import DatabaseManager
from dashboard.web_ui import start_dashboard
from utils.notifications import NotificationManager

class ASMSentinel:
    def __init__(self, config_path: str = 'config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.db = DatabaseManager(self.config['database']['path'])
        self.notifier = NotificationManager(self.config.get('notifications', {}))
        self.start_time = None
        
        # Initialize modules
        self.discovery = AssetDiscovery(self.config['organization']['domains'])
        self.dns_monitor = DNSMonitor()
        self.port_scanner = PortScanner(
            list(map(int, self.config['scanning']['ports'].split(','))),
            self.config['scanning']['threads']
        )
        self.tech_detector = TechDetector()
        self.ssl_monitor = SSLMonitor()
        self.cloud_scanner = CloudScanner()
        self.vuln_lookup = VulnLookup()
        self.risk_scorer = RiskScorer(self.config['risk_scoring']['weights'])
        self.screenshot_capture = ScreenshotCapture()
        
    def run_full_scan(self):
        """Execute complete ASM scan"""
        self.start_time = time.time()
        
        print("\n" + "="*60)
        print(f"🔍 ASM Sentinel Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
        
        # Step 1: Asset Discovery
        assets = self.discovery.discover_all()
        asset_ids = {}
        for asset in assets:
            asset_id = self.db.add_asset(asset['name'], asset['type'])
            asset_ids[asset['name']] = asset_id
            
        # Step 2: DNS Resolution
        dns_results = {}
        for asset in assets:
            ips = self.dns_monitor.resolve_a_records(asset['name'])
            if ips:
                dns_results[asset['name']] = ips
                
        # Step 3: Get live hosts
        live_hosts = [asset['name'] for asset in assets if self._is_live(asset['name'])]
        
        # Step 4: Port scanning
        port_results = self.port_scanner.scan_hosts(live_hosts)
        for host, ports in port_results.items():
            if host in asset_ids:
                for port in ports:
                    self.db.add_port(asset_ids[host], port)
                    
        # Step 5: Technology detection
        for host in live_hosts:
            if host in port_results and any(p in [80, 443, 8080, 8443] for p in port_results[host]):
                tech = self.tech_detector.detect(host)
                if host in asset_ids:
                    for tech_name in tech.values():
                        if isinstance(tech_name, str):
                            self.db.add_technology(asset_ids[host], tech_name)
                            
        # Step 6: SSL monitoring
        for host in live_hosts:
            if host in port_results and 443 in port_results[host]:
                ssl_info = self.ssl_monitor.check_certificate(host)
                if ssl_info['valid'] and ssl_info['days_left'] < 30:
                    self.db.add_alert(
                        'HIGH' if ssl_info['days_left'] < 7 else 'MEDIUM',
                        host,
                        'SSL Certificate',
                        f"SSL certificate expires in {ssl_info['days_left']} days"
                    )
                    
        # Step 7: Cloud exposure detection
        cloud_assets = self.cloud_scanner.check_public_storage(self.config['organization']['domains'][0].split('.')[0])
        for cloud_asset in cloud_assets:
            asset_id = self.db.add_asset(cloud_asset['name'], cloud_asset['type'])
            self.db.add_alert('HIGH', cloud_asset['name'], 'Cloud Exposure', f"Public {cloud_asset['type']} detected")
            
        # Step 8: Vulnerability lookup for detected technologies
        kev_list = self.vuln_lookup.get_kev_catalog()
        for host in live_hosts:
            if host in asset_ids:
                techs = self.db.get_assets()  # Simplified for demo
                for tech in techs:
                    if tech.get('technologies'):
                        vulns = self.vuln_lookup.lookup_by_technology(tech['technologies'].split(',')[0])
                        for vuln in vulns[:3]:  # Limit to first 3
                            if vuln['cve_id'] in kev_list:
                                self.db.add_alert('CRITICAL', host, 'Known Exploit', f"{vuln['cve_id']} is actively exploited")
                                
        # Step 9: Risk scoring
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for host in live_hosts:
            if host in asset_ids:
                asset_info = {
                    'internet_exposed': True,
                    'open_ports': port_results.get(host, []),
                    'admin_panels': [],
                    'ssl_expired': False
                }
                score = self.risk_scorer.calculate_score(asset_info)
                risk_level = self.risk_scorer.get_risk_level(score)
                risk_counts[risk_level] += 1
                
               
