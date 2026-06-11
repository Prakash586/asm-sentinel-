import ssl
import socket
from datetime import datetime
from typing import Dict, Optional
import OpenSSL
import cryptography

class SSLMonitor:
    def __init__(self):
        self.context = ssl.create_default_context()
        
    def check_certificate(self, hostname: str, port: int = 443) -> Dict:
        """Check SSL/TLS certificate details"""
        result = {
            'hostname': hostname,
            'valid': False,
            'expired': False,
            'expiring_soon': False,
            'days_left': 0,
            'issuer': '',
            'subject': '',
            'san': [],
            'cipher_suite': '',
            'protocol': '',
            'errors': []
        }
        
        try:
            # Connect and get certificate
            sock = socket.create_connection((hostname, port), timeout=5)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Certificate validity
                expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_date - datetime.now()).days
                
                result['valid'] = True
                result['days_left'] = days_left
                result['expired'] = days_left < 0
                result['expiring_soon'] = 0 < days_left < 30
                result['issuer'] = dict(x[0] for x in cert['issuer'])
                result['subject'] = dict(x[0] for x in cert['subject'])
                result['san'] = cert.get('subjectAltName', [])
                result['protocol'] = ssock.version()
                result['cipher_suite'] = ssock.cipher()[0]
                
        except ssl.SSLCertVerificationError as e:
            result['errors'].append(str(e))
        except socket.timeout:
            result['errors'].append("Connection timeout")
        except ConnectionRefusedError:
            result['errors'].append("Connection refused")
        except Exception as e:
            result['errors'].append(str(e))
            
        return result
    
    def get_weak_ciphers(self, hostname: str, port: int = 443) -> List[str]:
        """Detect weak cipher suites"""
        weak_ciphers = []
        test_ciphers = [
            'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5'
        ]
        
        try:
            sock = socket.create_connection((hostname, port), timeout=5)
            ctx = ssl.create_default_context()
            ctx.set_ciphers(':'.join(test_ciphers))
            
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                for cipher in test_ciphers:
                    if cipher in ssock.cipher()[0]:
                        weak_ciphers.append(cipher)
        except:
            pass
            
        return weak_ciphersimport ssl
import socket
from datetime import datetime
from typing import Dict, Optional
import OpenSSL
import cryptography

class SSLMonitor:
    def __init__(self):
        self.context = ssl.create_default_context()
        
    def check_certificate(self, hostname: str, port: int = 443) -> Dict:
        """Check SSL/TLS certificate details"""
        result = {
            'hostname': hostname,
            'valid': False,
            'expired': False,
            'expiring_soon': False,
            'days_left': 0,
            'issuer': '',
            'subject': '',
            'san': [],
            'cipher_suite': '',
            'protocol': '',
            'errors': []
        }
        
        try:
            # Connect and get certificate
            sock = socket.create_connection((hostname, port), timeout=5)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Certificate validity
                expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_date - datetime.now()).days
                
                result['valid'] = True
                result['days_left'] = days_left
                result['expired'] = days_left < 0
                result['expiring_soon'] = 0 < days_left < 30
                result['issuer'] = dict(x[0] for x in cert['issuer'])
                result['subject'] = dict(x[0] for x in cert['subject'])
                result['san'] = cert.get('subjectAltName', [])
                result['protocol'] = ssock.version()
                result['cipher_suite'] = ssock.cipher()[0]
                
        except ssl.SSLCertVerificationError as e:
            result['errors'].append(str(e))
        except socket.timeout:
            result['errors'].append("Connection timeout")
        except ConnectionRefusedError:
            result['errors'].append("Connection refused")
        except Exception as e:
            result['errors'].append(str(e))
            
        return result
    
    def get_weak_ciphers(self, hostname: str, port: int = 443) -> List[str]:
        """Detect weak cipher suites"""
        weak_ciphers = []
        test_ciphers = [
            'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5'
        ]
        
        try:
            sock = socket.create_connection((hostname, port), timeout=5)
            ctx = ssl.create_default_context()
            ctx.set_ciphers(':'.join(test_ciphers))
            
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                for cipher in test_ciphers:
                    if cipher in ssock.cipher()[0]:
                        weak_ciphers.append(cipher)
        except:
            pass
            
        return weak_ciphers
