import dns.resolver
import dns.reversename
from datetime import datetime
from typing import List, Dict, Optional

class DNSMonitor:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
    def resolve_a_records(self, hostname: str) -> List[str]:
        """Resolve A records for a hostname"""
        ips = []
        try:
            answers = self.resolver.resolve(hostname, 'A')
            for answer in answers:
                ips.append(str(answer))
        except:
            pass
        return ips
    
    def resolve_ptr_records(self, ip: str) -> List[str]:
        """Resolve PTR records for an IP"""
        hostnames = []
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, 'PTR')
            for answer in answers:
                hostnames.append(str(answer).rstrip('.'))
        except:
            pass
        return hostnames
    
    def get_dnssec_info(self, domain: str) -> Dict:
        """Check DNSSEC configuration"""
        info = {
            'enabled': False,
            'algorithms': [],
            'valid': False
        }
        try:
            answers = self.resolver.resolve(domain, 'DNSKEY')
            info['enabled'] = True
            for answer in answers:
                info['algorithms'].append(answer.algorithm)
            info['valid'] = True
        except dns.resolver.NXDOMAIN:
            pass
        except:
            pass
        return info
    
    def detect_dns_changes(self, previous_records: Dict, current_records: Dict) -> Dict:
        """Detect changes in DNS records"""
        changes = {
            'added': [],
            'removed': [],
            'modified': []
        }
        
        for hostname, ips in current_records.items():
            if hostname not in previous_records:
                changes['added'].append(hostname)
            elif set(ips) != set(previous_records[hostname]):
                changes['modified'].append(hostname)
                
        for hostname in previous_records:
            if hostname not in current_records:
                changes['removed'].append(hostname)
                
        return changes
