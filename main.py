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
                
                # Update asset with risk score
                self.db.add_asset(host, 'subdomain', risk_score=score, risk_level=risk_level)
                
                # Send critical alerts
                if risk_level == 'CRITICAL':
                    self.notifier.send_critical_alert(
                        host,
                        'High Risk Asset',
                        f"Risk score: {score}/100 - Immediate investigation required"
                    )
                    
        # Step 10: Save scan history
        duration = int(time.time() - self.start_time)
        self.db.add_scan_history(
            len(live_hosts),
            len(live_hosts),
            risk_counts['CRITICAL'],
            risk_counts['HIGH'],
            risk_counts['MEDIUM'],
            risk_counts['LOW'],
            duration
        )
        
        # Step 11: Generate report
        self._generate_summary_report(assets, port_results, risk_counts, duration)
        
        print(f"\n✅ Scan completed in {duration} seconds!")
        print(f"   📊 Found {len(live_hosts)} live assets")
        print(f"   🔴 Critical: {risk_counts['CRITICAL']}")
        print(f"   🟠 High: {risk_counts['HIGH']}")
        print(f"   🟡 Medium: {risk_counts['MEDIUM']}")
        print(f"   🟢 Low: {risk_counts['LOW']}")
        
    def _is_live(self, host: str) -> bool:
        """Check if a host is reachable"""
        import socket
        try:
            socket.gethostbyname(host)
            return True
        except:
            return False
            
    def _generate_summary_report(self, assets, ports, risk_counts, duration):
        """Generate summary report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"reports/asm_summary_{timestamp}.txt"
        
        os.makedirs('reports', exist_ok=True)
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("ASM SENTINEL SCAN REPORT\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {duration} seconds\n")
            f.write("="*60 + "\n\n")
            
            f.write("ASSET SUMMARY\n")
            f.write(f"Total Discovered: {len(assets)}\n")
            f.write(f"Live Hosts: {len(ports)}\n\n")
            
            f.write("RISK DISTRIBUTION\n")
            f.write(f"CRITICAL: {risk_counts['CRITICAL']}\n")
            f.write(f"HIGH: {risk_counts['HIGH']}\n")
            f.write(f"MEDIUM: {risk_counts['MEDIUM']}\n")
            f.write(f"LOW: {risk_counts['LOW']}\n\n")
            
            f.write("TOP OPEN PORTS\n")
            all_ports = []
            for host_ports in ports.values():
                all_ports.extend(host_ports)
            from collections import Counter
            for port, count in Counter(all_ports).most_common(10):
                f.write(f"  Port {port}: {count} hosts\n")
                
        print(f"📄 Report saved: {report_file}")
        
    def start_scheduler(self):
        """Start scheduled scanning"""
        schedule.every().day.at("00:00").do(self.run_full_scan)
        schedule.every().day.at("12:00").do(self.run_full_scan)
        
        print("⏰ Scheduler started. Running scans at 00:00 and 12:00 daily")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n👋 Shutting down scheduler...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ASM Sentinel - Attack Surface Management Platform')
    parser.add_argument('--scan', action='store_true', help='Run a single scan')
    parser.add_argument('--dashboard', action='store_true', help='Start web dashboard')
    parser.add_argument('--scheduler', action='store_true', help='Start scheduled scanning')
    
    args = parser.parse_args()
    
    asm = ASMSentinel()
    
    if args.scan:
        asm.run_full_scan()
    elif args.dashboard:
        start_dashboard(asm.db)
    elif args.scheduler:
        asm.start_scheduler()
    else:
        parser.print_help()
