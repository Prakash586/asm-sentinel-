#!/usr/bin/env python3

import yaml
import time
import schedule
import argparse
import os
from datetime import datetime
from typing import Dict, List, Optional

# Import all modules from the modules folder
from modules import (
    AssetDiscovery,
    DNSMonitor,
    PortScanner,
    TechDetector,
    SSLMonitor,
    ScreenshotCapture,
    CloudScanner,
    VulnLookup,
    RiskScorer,
    DatabaseManager
)

class ASMSentinel:
    """Main ASM Sentinel Class - Attack Surface Management Platform"""
    
    def __init__(self, config_path: str = 'config.yaml'):
        """Initialize ASM Sentinel with configuration"""
        
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Initialize database
        db_path = self.config.get('database', {}).get('path', 'database/assets.db')
        self.db = DatabaseManager(db_path)
        
        # Initialize all modules
        self.discovery = AssetDiscovery(self.config['organization']['domains'])
        self.dns_monitor = DNSMonitor()
        
        # Parse ports from config
        ports_str = self.config['scanning']['ports']
        self.ports = list(map(int, ports_str.split(',')))
        
        self.port_scanner = PortScanner(
            self.ports,
            self.config['scanning']['threads']
        )
        
        self.tech_detector = TechDetector()
        self.ssl_monitor = SSLMonitor()
        self.cloud_scanner = CloudScanner()
        self.vuln_lookup = VulnLookup()
        self.risk_scorer = RiskScorer(self.config['risk_scoring']['weights'])
        
        # Initialize screenshot capture (optional)
        try:
            self.screenshot_capture = ScreenshotCapture()
        except Exception as e:
            print(f"[!] Screenshot capture disabled: {e}")
            self.screenshot_capture = None
        
        self.start_time = None
        self.results = {}
        
    def run_full_scan(self):
        """Execute complete ASM scan"""
        self.start_time = time.time()
        
        print("\n" + "="*70)
        print(f"🔍 ASM Sentinel Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
        
        try:
            # Step 1: Asset Discovery
            assets = self._step_asset_discovery()
            
            # Step 2: DNS Resolution
            dns_results = self._step_dns_resolution(assets)
            
            # Step 3: Live Host Detection
            live_hosts = self._step_live_host_detection(assets)
            
            # Step 4: Port Scanning
            port_results = self._step_port_scanning(live_hosts)
            
            # Step 5: Technology Detection
            tech_results = self._step_tech_detection(live_hosts, port_results)
            
            # Step 6: SSL Monitoring
            ssl_results = self._step_ssl_monitoring(live_hosts, port_results)
            
            # Step 7: Cloud Exposure Detection
            cloud_assets = self._step_cloud_detection()
            
            # Step 8: Vulnerability Lookup
            vuln_results = self._step_vulnerability_lookup(tech_results)
            
            # Step 9: Risk Scoring
            risk_results = self._step_risk_scoring(assets, port_results, tech_results, ssl_results)
            
            # Step 10: Save to Database
            self._step_save_to_database(assets, port_results, tech_results, ssl_results, vuln_results, risk_results)
            
            # Step 11: Generate Reports
            self._step_generate_reports(assets, live_hosts, port_results, tech_results, risk_results)
            
            # Step 12: Send Alerts
            self._step_send_alerts(risk_results, ssl_results, cloud_assets)
            
            # Step 13: Capture Screenshots (optional)
            if self.screenshot_capture:
                self._step_capture_screenshots(live_hosts)
            
            # Step 14: Record scan history
            duration = int(time.time() - self.start_time)
            self._record_scan_history(assets, live_hosts, risk_results, duration)
            
            # Print summary
            self._print_scan_summary(assets, live_hosts, risk_results, duration)
            
        except Exception as e:
            print(f"\n❌ Scan failed with error: {e}")
            import traceback
            traceback.print_exc()
            
    def _step_asset_discovery(self) -> List[Dict]:
        """Step 1: Discover assets"""
        print("[1/14] Asset Discovery in progress...")
        assets = self.discovery.discover_all()
        print(f"       ✅ Discovered {len(assets)} unique assets")
        return assets
    
    def _step_dns_resolution(self, assets: List[Dict]) -> Dict:
        """Step 2: DNS Resolution"""
        print("[2/14] DNS Resolution in progress...")
        dns_results = {}
        for asset in assets[:50]:  # Limit for performance
            ips = self.dns_monitor.resolve_a_records(asset['name'])
            if ips:
                dns_results[asset['name']] = ips
        print(f"       ✅ Resolved {len(dns_results)} assets to IPs")
        return dns_results
    
    def _step_live_host_detection(self, assets: List[Dict]) -> List[str]:
        """Step 3: Detect live hosts"""
        print("[3/14] Live Host Detection in progress...")
        live_hosts = []
        for asset in assets:
            if self._is_live(asset['name']):
                live_hosts.append(asset['name'])
        print(f"       ✅ Found {len(live_hosts)} live hosts")
        return live_hosts
    
    def _step_port_scanning(self, live_hosts: List[str]) -> Dict:
        """Step 4: Port scanning"""
        print(f"[4/14] Port Scanning in progress (scanning {len(live_hosts)} hosts)...")
        port_results = self.port_scanner.scan_hosts(live_hosts)
        
        # Count total open ports
        total_ports = sum(len(ports) for ports in port_results.values())
        print(f"       ✅ Found {total_ports} open ports across {len(port_results)} hosts")
        return port_results
    
    def _step_tech_detection(self, live_hosts: List[str], port_results: Dict) -> Dict:
        """Step 5: Technology detection"""
        print("[5/14] Technology Detection in progress...")
        tech_results = {}
        
        for host in live_hosts:
            # Check if host has web ports
            has_web_port = False
            if host in port_results:
                for port in port_results[host]:
                    if port in [80, 443, 8080, 8443, 3000, 5000, 8000]:
                        has_web_port = True
                        break
            
            if has_web_port:
                tech_results[host] = self.tech_detector.detect(host)
        
        print(f"       ✅ Analyzed {len(tech_results)} web services")
        return tech_results
    
    def _step_ssl_monitoring(self, live_hosts: List[str], port_results: Dict) -> Dict:
        """Step 6: SSL monitoring"""
        print("[6/14] SSL Monitoring in progress...")
        ssl_results = {}
        
        for host in live_hosts:
            if host in port_results and 443 in port_results[host]:
                ssl_results[host] = self.ssl_monitor.check_certificate(host)
        
        # Count expiring certificates
        expiring = sum(1 for r in ssl_results.values() if r.get('expiring_soon', False))
        expired = sum(1 for r in ssl_results.values() if r.get('expired', False))
        print(f"       ✅ Checked {len(ssl_results)} SSL certificates (Expiring: {expiring}, Expired: {expired})")
        return ssl_results
    
    def _step_cloud_detection(self) -> List[Dict]:
        """Step 7: Cloud exposure detection"""
        print("[7/14] Cloud Exposure Detection in progress...")
        domain_prefix = self.config['organization']['domains'][0].split('.')[0]
        cloud_assets = self.cloud_scanner.check_public_storage(domain_prefix)
        print(f"       ✅ Found {len(cloud_assets)} exposed cloud assets")
        return cloud_assets
    
    def _step_vulnerability_lookup(self, tech_results: Dict) -> Dict:
        """Step 8: Vulnerability lookup"""
        print("[8/14] Vulnerability Lookup in progress...")
        vuln_results = {}
        
        # Get KEV catalog
        kev_list = self.vuln_lookup.get_kev_catalog()
        print(f"       📋 Retrieved {len(kev_list)} known exploited vulnerabilities")
        
        # Check each technology
        for host, tech in tech_results.items():
            host_vulns = []
            for tech_name in tech.values():
                if isinstance(tech_name, str):
                    vulns = self.vuln_lookup.lookup_by_technology(tech_name)
                    for vuln in vulns[:2]:  # Limit to first 2
                        if vuln['cve_id'] in kev_list:
                            vuln['kev'] = True
                        host_vulns.append(vuln)
            if host_vulns:
                vuln_results[host] = host_vulns
        
        total_vulns = sum(len(v) for v in vuln_results.values())
        print(f"       ✅ Found {total_vulns} potential vulnerabilities")
        return vuln_results
    
    def _step_risk_scoring(self, assets: List[Dict], port_results: Dict, 
                          tech_results: Dict, ssl_results: Dict) -> Dict:
        """Step 9: Risk scoring"""
        print("[9/14] Risk Scoring in progress...")
        risk_results = {}
        
        for asset in assets:
            host = asset['name']
            asset_info = {
                'internet_exposed': True,
                'open_ports': port_results.get(host, []),
                'admin_panels': tech_results.get(host, {}).get('admin_panels', []),
                'ssl_expired': ssl_results.get(host, {}).get('expired', False),
                'ssl_expiring_soon': ssl_results.get(host, {}).get('expiring_soon', False),
                'outdated_software': False,  # Would need version comparison
                'default_login': '/login' in str(tech_results.get(host, {})),
                'vulnerabilities': []  # Would add from vuln_results
            }
            
            score = self.risk_scorer.calculate_score(asset_info)
            level = self.risk_scorer.get_risk_level(score)
            
            risk_results[host] = {
                'score': score,
                'level': level,
                'details': asset_info
            }
        
        # Count risk levels
        critical = sum(1 for r in risk_results.values() if r['level'] == 'CRITICAL')
        high = sum(1 for r in risk_results.values() if r['level'] == 'HIGH')
        medium = sum(1 for r in risk_results.values() if r['level'] == 'MEDIUM')
        low = sum(1 for r in risk_results.values() if r['level'] == 'LOW')
        
        print(f"       ✅ Risk scores calculated: Critical:{critical} High:{high} Medium:{medium} Low:{low}")
        return risk_results
    
    def _step_save_to_database(self, assets: List[Dict], port_results: Dict,
                               tech_results: Dict, ssl_results: Dict,
                               vuln_results: Dict, risk_results: Dict):
        """Step 10: Save results to database"""
        print("[10/14] Saving to Database...")
        
        asset_ids = {}
        
        # Save assets
        for asset in assets:
            host = asset['name']
            risk_info = risk_results.get(host, {'score': 0, 'level': 'LOW'})
            asset_id = self.db.add_asset(
                host, 
                asset['type'],
                risk_score=risk_info['score'],
                risk_level=risk_info['level']
            )
            asset_ids[host] = asset_id
        
        # Save ports
        for host, ports in port_results.items():
            if host in asset_ids:
                for port in ports:
                    self.db.add_port(asset_ids[host], port)
        
        # Save technologies
        for host, tech in tech_results.items():
            if host in asset_ids:
                for key, value in tech.items():
                    if isinstance(value, str):
                        self.db.add_technology(asset_ids[host], key, value)
        
        # Save SSL info
        for host, ssl in ssl_results.items():
            if host in asset_ids and ssl.get('valid'):
                # Would add to ssl_certificates table
                pass
        
        # Save vulnerabilities
        for host, vulns in vuln_results.items():
            if host in asset_ids:
                for vuln in vulns:
                    self.db.add_vulnerability(
                        asset_ids[host],
                        vuln['cve_id'],
                        'HIGH',  # Would determine severity
                        7.5,     # Would get from API
                        vuln['description']
                    )
        
        print(f"       ✅ Saved {len(asset_ids)} assets to database")
    
    def _step_generate_reports(self, assets: List[Dict], live_hosts: List[str],
                               port_results: Dict, tech_results: Dict, 
                               risk_results: Dict):
        """Step 11: Generate reports"""
        print("[11/14] Generating Reports...")
        
        # Create reports directory
        os.makedirs('reports', exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate HTML report
        html_report = f"reports/asm_report_{timestamp}.html"
        self._generate_html_report(html_report, assets, live_hosts, port_results, tech_results, risk_results)
        
        # Generate JSON report
        json_report = f"reports/asm_report_{timestamp}.json"
        self._generate_json_report(json_report, assets, live_hosts, port_results, tech_results, risk_results)
        
        print(f"       ✅ HTML report: {html_report}")
        print(f"       ✅ JSON report: {json_report}")
    
    def _step_send_alerts(self, risk_results: Dict, ssl_results: Dict, cloud_assets: List[Dict]):
        """Step 12: Send alerts for critical findings"""
        print("[12/14] Checking for Critical Alerts...")
        
        alerts_sent = 0
        
        # Check for critical risk assets
        for host, risk in risk_results.items():
            if risk['level'] == 'CRITICAL':
                print(f"       🔴 CRITICAL: {host} - Risk Score: {risk['score']}")
                alerts_sent += 1
        
        # Check for expired SSL
        for host, ssl in ssl_results.items():
            if ssl.get('expired', False):
                print(f"       🔴 EXPIRED SSL: {host}")
                alerts_sent += 1
            elif ssl.get('expiring_soon', False):
                print(f"       🟡 EXPIRING SOON: {host} - {ssl.get('days_left', 0)} days left")
        
        # Check for exposed cloud assets
        for cloud_asset in cloud_assets:
            print(f"       🔴 EXPOSED CLOUD: {cloud_asset['name']} ({cloud_asset['type']})")
            alerts_sent += 1
        
        if alerts_sent == 0:
            print("       ✅ No critical alerts detected")
        else:
            print(f"       📢 Sent {alerts_sent} alerts")
    
    def _step_capture_screenshots(self, live_hosts: List[str]):
        """Step 13: Capture screenshots (optional)"""
        print("[13/14] Capturing Screenshots...")
        
        screenshots_taken = 0
        for host in live_hosts[:10]:  # Limit to first 10 hosts
            try:
                url = f"http://{host}"
                result = self.screenshot_capture.capture(url)
                if result['success']:
                    screenshots_taken += 1
            except:
                pass
        
        print(f"       ✅ Captured {screenshots_taken} screenshots")
    
    def _record_scan_history(self, assets: List[Dict], live_hosts: List[str],
                             risk_results: Dict, duration: int):
        """Record scan history in database"""
        print("[14/14] Recording Scan History...")
        
        # Count risk levels
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for risk in risk_results.values():
            risk_counts[risk['level']] += 1
        
        self.db.add_scan_history(
            len(assets),
            len(live_hosts),
            risk_counts['CRITICAL'],
            risk_counts['HIGH'],
            risk_counts['MEDIUM'],
            risk_counts['LOW'],
            duration
        )
        
        print("       ✅ Scan history recorded")
    
    def _print_scan_summary(self, assets: List[Dict], live_hosts: List[str],
                           risk_results: Dict, duration: int):
        """Print scan summary"""
        print("\n" + "="*70)
        print("📊 SCAN SUMMARY")
        print("="*70)
        
        # Asset statistics
        print(f"\n📦 Asset Statistics:")
        print(f"   Total Discovered: {len(assets)}")
        print(f"   Live Hosts: {len(live_hosts)}")
        
        # Risk distribution
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for risk in risk_results.values():
            risk_counts[risk['level']] += 1
        
        print(f"\n⚠️  Risk Distribution:")
        print(f"   🔴 CRITICAL: {risk_counts['CRITICAL']}")
        print(f"   🟠 HIGH: {risk_counts['HIGH']}")
        print(f"   🟡 MEDIUM: {risk_counts['MEDIUM']}")
        print(f"   🟢 LOW: {risk_counts['LOW']}")
        
        # Top critical assets
        critical_assets = [(host, risk['score']) for host, risk in risk_results.items() 
                          if risk['level'] == 'CRITICAL']
        if critical_assets:
            print(f"\n🎯 Top Critical Assets:")
            for host, score in sorted(critical_assets, key=lambda x: x[1], reverse=True)[:5]:
                print(f"   • {host} (Score: {score})")
        
        print(f"\n⏱️  Scan Duration: {duration} seconds")
        print("="*70 + "\n")
    
    def _generate_html_report(self, filename: str, assets: List[Dict], live_hosts: List[str],
                              port_results: Dict, tech_results: Dict, risk_results: Dict):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>ASM Sentinel Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        h1 {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #764ba2;
            margin-top: 30px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #667eea;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .critical {{ color: #ff4444; font-weight: bold; }}
        .high {{ color: #ff8800; font-weight: bold; }}
        .medium {{ color: #ffcc00; font-weight: bold; }}
        .low {{ color: #44ff44; font-weight: bold; }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #999;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ ASM Sentinel Report</h1>
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{len(assets)}</div>
                <div class="stat-label">Total Assets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(live_hosts)}</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{sum(len(ports) for ports in port_results.values())}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(tech_results)}</div>
                <div class="stat-label">Technologies</div>
            </div>
        </div>
        
        <h2>📊 Risk Assessment</h2>
        <table>
            <thead>
                <tr>
                    <th>Asset</th>
                    <th>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Open Ports</th>
                    <th>Technologies</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for host, risk in sorted(risk_results.items(), key=lambda x: x[1]['score'], reverse=True)[:20]:
            risk_class = risk['level'].lower()
            ports = ', '.join(map(str, port_results.get(host, [])))
            techs = ', '.join(tech_results.get(host, {}).values()) if host in tech_results else '-'
            
            html += f"""
                <tr>
                    <td>{host}</td>
                    <td>{risk['score']}</td>
                    <td class="{risk_class}">{risk['level']}</td>
                    <td>{ports}</td>
                    <td>{techs}</td>
                </tr>
            """
        
        html += f"""
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by ASM Sentinel - Attack Surface Management Platform</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html)
    
    def _generate_json_report(self, filename: str, assets: List[Dict], live_hosts: List[str],
                              port_results: Dict, tech_results: Dict, risk_results: Dict):
        """Generate JSON report"""
        import json
        
        report = {
            'scan_time': datetime.now().isoformat(),
            'summary': {
                'total_assets': len(assets),
                'live_hosts': len(live_hosts),
                'total_open_ports': sum(len(ports) for ports in port_results.values()),
                'technologies_detected': len(tech_results)
            },
            'risk_distribution': {},
            'assets': []
        }
        
        # Calculate risk distribution
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for risk in risk_results.values():
            risk_counts[risk['level']] += 1
        report['risk_distribution'] = risk_counts
        
        # Add asset details
        for host, risk in risk_results.items():
            report['assets'].append({
                'name': host,
                'risk_score': risk['score'],
                'risk_level': risk['level'],
                'open_ports': port_results.get(host, []),
                'technologies': tech_results.get(host, {})
            })
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
    
    def _is_live(self, host: str) -> bool:
        """Check if a host is reachable"""
        import socket
        try:
            socket.gethostbyname(host)
            return True
        except:
            return False
    
    def start_dashboard(self):
        """Start the web dashboard"""
        from dashboard.web_ui import start_dashboard
        start_dashboard(self.db)
    
    def start_scheduler(self):
        """Start scheduled scanning"""
        print("\n⏰ ASM Sentinel Scheduler Started")
        print("="*50)
        print("Schedule:")
        print("  • Daily at 00:00 (Midnight)")
        print("  • Daily at 12:00 (Noon)")
        print("\nPress Ctrl+C to stop\n")
        
        # Schedule scans
        schedule.every().day.at("00:00").do(self.run_full_scan)
        schedule.every().day.at("12:00").do(self.run_full_scan)
        
        # Run initial scan immediately
        print("Running initial scan...")
        self.run_full_scan()
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n\n👋 Scheduler stopped. Goodbye!")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='ASM Sentinel - Attack Surface Management Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scan              # Run a single scan
  python main.py --dashboard         # Start web dashboard
  python main.py --scheduler         # Start scheduled scanning
  
For more information, visit: https://github.com/Prakash586/asm-sentinel
        """
    )
    
    parser.add_argument('--scan', action='store_true', help='Run a single scan')
    parser.add_argument('--dashboard', action='store_true', help='Start web dashboard')
    parser.add_argument('--scheduler', action='store_true', help='Start scheduled scanning')
    parser.add_argument('--config', default='config.yaml', help='Path to config file')
    
    args = parser.parse_args()
    
    # Check if config file exists
    if not os.path.exists(args.config):
        print(f"❌ Config file not found: {args.config}")
        print("   Please create config.yaml first")
        sys.exit(1)
    
    # Initialize ASM Sentinel
    asm = ASMSentinel(args.config)
    
    # Execute command
    if args.scan:
        asm.run_full_scan()
    elif args.dashboard:
        asm.start_dashboard()
    elif args.scheduler:
        asm.start_scheduler()
    else:
        parser.print_help()

if __name__ == "__main__":
    import sys
    main()
