import requests
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional

class VulnLookup:
    def __init__(self):
        self.cve_cache = {}
        
    def lookup_by_cve(self, cve_id: str) -> Dict:
        """Lookup CVE details from NVD"""
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
            
        result = {
            'cve_id': cve_id,
            'description': '',
            'cvss_score': 0,
            'severity': 'UNKNOWN',
            'published': '',
            'references': []
        }
        
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']
                    result['description'] = vuln.get('descriptions', [{}])[0].get('value', '')
                    
                    metrics = vuln.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                    if cvss_v3:
                        result['cvss_score'] = cvss_v3.get('baseScore', 0)
                        result['severity'] = cvss_v3.get('baseSeverity', 'UNKNOWN')
                        
                    result['published'] = vuln.get('published', '')
                    result['references'] = [ref.get('url', '') for ref in vuln.get('references', [])]
                    
            self.cve_cache[cve_id] = result
            
        except Exception as e:
            print(f"[-] CVE lookup failed for {cve_id}: {e}")
            
        return result
    
    def lookup_by_technology(self, technology: str, version: str = None) -> List[Dict]:
        """Find CVEs for specific technology versions"""
        cves = []
        
        # Search using NVD API
        search_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={technology}"
        
        try:
            response = requests.get(search_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln['cve']
                    
                    # Filter by version if specified
                    if version:
                        configurations = cve_data.get('configurations', [])
                        version_match = False
                        
                        for config in configurations:
                            for node in config.get('nodes', []):
                                for cpe in node.get('cpeMatch', []):
                                    if version in cpe.get('criteria', ''):
                                        version_match = True
                                        break
                                        
                        if not version_match:
                            continue
                            
                    cves.append({
                        'cve_id': cve_data['id'],
                        'description': cve_data.get('descriptions', [{}])[0].get('value', '')[:200],
                        'published': cve_data.get('published', '')
                    })
                    
        except Exception as e:
            print(f"[-] Technology lookup failed: {e}")
            
        return cves
    
    def get_kev_catalog(self) -> List[str]:
        """Get CISA Known Exploited Vulnerabilities"""
        kev_list = []
        
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    kev_list.append(vuln.get('cveID', ''))
                    
        except Exception as e:
            print(f"[-] Failed to fetch KEV catalog: {e}")
            
        return kev_list
    
    def check_recent_vulnerabilities(self, days: int = 7) -> List[Dict]:
        """Get recently published vulnerabilities"""
        from_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={from_date}"
        
        recent_cves = []
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln['cve']
                    recent_cves.append({
                        'cve_id': cve_data['id'],
                        'severity': cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                        'description': cve_data.get('descriptions', [{}])[0].get('value', '')[:150]
                    })
        except:
            pass
            
        return recent_cves
