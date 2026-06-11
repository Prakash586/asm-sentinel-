#!/usr/bin/env python3

import yaml
import json
import schedule
import time
from datetime import datetime
from modules import *
from database.db_manager import DatabaseManager
from dashboard.web_ui import start_dashboard

class ASMSentinel:
    def __init__(self, config_path: str = 'config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.db = DatabaseManager(self.config['database']['path'])
        self.discovery = AssetDiscovery(self.config['organization']['domains'])
        self.port_scanner = PortScanner(
            list(map(int, self.config['scanning']['ports'].split(','))),
            self.config['scanning']['threads']
        )
        self.tech_detector = TechDetector()
        self.ssl_monitor = SSLMonitor()
        self.risk_scorer = RiskScorer(self.config['risk_scoring']['weights'])
        
    def run_full_scan(self):
        """Execute complete ASM scan"""
        print("\n" + "="*60)
        print(f"ASM Sentinel Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
        
        # Step 1: Asset Discovery
        assets = self.discovery.discover_all()
        for asset in assets:
            self.db.add_asset(asset['name'], asset['type'])
            
        # Step 2: Get live hosts
        live_hosts = self._check_live_hosts([a['name'] for a in assets])
        
        # Step 3: Port scanning
        port_results = self.port_scanner.scan_hosts(live_hosts)
        
        # Step 4: Technology detection
        tech_results = {}
        for host in live_hosts:
            if host in port_results and (80 in port_results[host] or 443 in port_results[host]):
                tech_results[host] = self.tech_detector.detect(host)
                
        # Step 5: SSL monitoring
        ssl_results = {}
        for host in live_hosts:
            if host in port_results and 443 in port_results[host]:
                ssl_results[host] = self.ssl_monitor.check_certificate(host)
                
        # Step 6: Risk scoring
        risk_scores = {}
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for host in live_hosts:
            asset_info = {
                'internet_exposed': True,
                'open_ports': port_results.get(host, []),
                'admin_panels': tech_results.get(host, {}).get('admin_panels', []),
                'ssl_expired': ssl_results.get(host, {}).get('expired', False),
            }
            score = self.risk_scorer.calculate_score(asset_info)
            risk_level = self.risk_scorer.get_risk_level(score)
            risk_scores[host] = {'score': score, 'level': risk_level}
            risk_counts[risk_level] += 1
            
        # Step 7: Save scan history
        self.db.add_scan_history(
            len(live_hosts),
            risk_counts['CRITICAL'],
            risk_counts['HIGH'],
            risk_counts['MEDIUM'],
            risk_counts['LOW']
        )
        
        # Step 8: Generate report
        self._generate_report(assets, port_results, tech_results, ssl_results, risk_scores)
        
        print(f"\n[+] Scan completed! Found {len(live_hosts)} live assets")
        print(f"    Critical: {risk_counts['CRITICAL']}")
        print(f"    High: {risk_counts['HIGH']}")
        print(f"    Medium: {risk_counts['MEDIUM']}")
        print(f"    Low: {risk_counts['LOW']}")
        
    def _check_live_hosts(self, hosts: List[str]) -> List[str]:
        """Check which hosts are live"""
        live = []
        for host in hosts:
            if self._is_live(host):
                live.append(host)
        return live
        
    def _is_live(self, host: str) -> bool:
        """Check if a host is reachable"""
        import socket
        try:
            socket.gethostbyname(host)
            return True
        except:
            return False
            
    def _generate_report(self, assets, ports, tech, ssl, risk):
        """Generate HTML report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"reports/asm_report_{timestamp}.html"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ASM Sentinel Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                .critical {{ background-color: #ff4444; }}
                .high {{ background-color: #ff8800; }}
                .medium {{ background-color: #ffcc00; }}
                .low {{ background-color: #44ff44; }}
            </style>
        </head>
        <body>
            <h1>ASM Sentinel Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h1>
            
            <h2>Summary</h2>
            <table>
                <tr><th>Total Assets</th><td>{len(assets)}</td></tr>
                <tr><th>Live Hosts</th><td>{len(ports)}</td></tr>
            </table>
            
            <h2>Risk Assessment</h2>
            <table>
                <tr>
                    <th>Host</th>
                    <th>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Open Ports</th>
                    <th>Technologies</th>
                </tr>
        """
        
        for host, score_info in risk.items():
            risk_class = score_info['level'].lower()
            ports_str = ', '.join(map(str, ports.get(host, [])))
            tech_str = ', '.join(tech.get(host, {}).get('web_server', 'Unknown'))
            
            html += f"""
                <tr class="{risk_class}">
                    <td>{host}</td>
                    <td>{score_info['score']}</td>
                    <td>{score_info['level']}</td>
                    <td>{ports_str}</td>
                    <td>{tech_str}</td>
                </tr>
            """
            
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(report_file, 'w') as f:
            f.write(html)
            
        print(f"[+] Report saved: {report_file}")
        
    def start_scheduler(self):
        """Start scheduled scanning"""
        schedule.every().day.at("00:00").do(self.run_full_scan)
        schedule.every().day.at("12:00").do(self.run_full_scan)
        
        print("[+] Scheduler started. Running scans at 00:00 and 12:00 daily")
        
        while True:
            schedule.run_pending()
            time.sleep(60)

if __name__ == "__main__":
    import sys
    
    asm = ASMSentinel()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--scan':
            asm.run_full_scan()
        elif sys.argv[1] == '--dashboard':
            start_dashboard(asm.db)
        elif sys.argv[1] == '--scheduler':
            asm.start_scheduler()
    else:
        print("Usage:")
        print("  python main.py --scan        # Run one-time scan")
        print("  python main.py --dashboard   # Start web dashboard")
        print("  python main.py --scheduler   # Start scheduled scanning")
