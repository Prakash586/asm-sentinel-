import nmap
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

class PortScanner:
    def __init__(self, ports: List[int], threads: int = 50):
        self.ports = ports
        self.threads = threads
        self.nm = nmap.PortScanner()
        
    def scan_hosts(self, hosts: List[str]) -> Dict[str, List[int]]:
        """Scan multiple hosts for open ports"""
        print(f"[+] Scanning {len(hosts)} hosts for open ports...")
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_single, host): host for host in hosts}
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    ports = future.result()
                    if ports:
                        results[host] = ports
                        print(f"  [+] {host}: {len(ports)} open ports")
                except Exception as e:
                    print(f"  [-] {host}: {e}")
                    
        return results
    
    def _scan_single(self, host: str) -> List[int]:
        """Scan a single host for open ports"""
        open_ports = []
        
        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
                
        return open_ports
    
    def detailed_scan(self, host: str, ports: List[int]) -> Dict:
        """Perform detailed nmap scan on specific ports"""
        try:
            port_str = ','.join(map(str, ports))
            self.nm.scan(host, port_str, arguments='-sV -sC')
            return self.nm[host]
        except Exception as e:
            print(f"[-] Detailed scan failed for {host}: {e}")
            return {}
