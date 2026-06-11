import requests
import json
import subprocess
import dns.resolver
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

class AssetDiscovery:
    def __init__(self, domains: List[str]):
        self.domains = domains
        self.assets = []
        
    def discover_all(self) -> List[Dict]:
        """Discover all assets across configured domains"""
        print("[+] Starting Asset Discovery...")
        
        # Method 1: crt.sh Certificate Transparency
        self._crt_sh_discovery()
        
        # Method 2: DNS Bruteforce
        self._dns_bruteforce()
        
        # Method 3: Subfinder (if installed)
        self._subfinder_discovery()
        
        print(f"[+] Discovered {len(self.assets)} unique assets")
        return self.assets
    
    def _crt_sh_discovery(self):
        """Query crt.sh for certificate data"""
        for domain in self.domains:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        if name:
                            for subdomain in name.split('\n'):
                                if domain in subdomain:
                                    self._add_asset({
                                        'type': 'subdomain',
                                        'name': subdomain.strip(),
                                        'source': 'crt.sh'
                                    })
            except Exception as e:
                print(f"[-] crt.sh error for {domain}: {e}")
    
    def _dns_bruteforce(self):
        """Bruteforce common subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'blog', 'dev',
            'staging', 'test', 'admin', 'portal', 'cdn', 'static', 'media', 'app', 'vpn',
            'remote', 'secure', 'support', 'shop', 'store', 'cloud', 'docs', 'git', 'jenkins'
        ]
        
        for domain in self.domains:
            for sub in common_subdomains:
                full_domain = f"{sub}.{domain}"
                try:
                    dns.resolver.resolve(full_domain, 'A')
                    self._add_asset({
                        'type': 'subdomain',
                        'name': full_domain,
                        'source': 'dns_bruteforce'
                    })
                except:
                    pass
    
    def _subfinder_discovery(self):
        """Use subfinder tool if available"""
        for domain in self.domains:
            try:
                result = subprocess.run(
                    ['subfinder', '-d', domain, '-silent'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if line.strip():
                            self._add_asset({
                                'type': 'subdomain',
                                'name': line.strip(),
                                'source': 'subfinder'
                            })
            except FileNotFoundError:
                print("[!] subfinder not installed, skipping")
            except Exception as e:
                print(f"[-] subfinder error: {e}")
    
    def _add_asset(self, asset: Dict):
        """Add unique asset to list"""
        if not any(a.get('name') == asset['name'] for a in self.assets):
            self.assets.append(asset)
