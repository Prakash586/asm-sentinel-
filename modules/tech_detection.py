import requests
from typing import Dict, List

class TechDetector:
    def __init__(self):
        self.technologies = {}
        
    def detect(self, host: str, port: int = 80) -> Dict:
        """Detect technologies used by a host"""
        results = {}
        
        # Try HTTP/HTTPS
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{host}:{port}"
                response = requests.get(url, timeout=5, verify=False)
                
                # Check server header
                server = response.headers.get('Server', '')
                if server:
                    results['web_server'] = server
                
                # Check framework
                if 'X-Powered-By' in response.headers:
                    results['framework'] = response.headers['X-Powered-By']
                
                # Check for CMS
                if '/wp-content/' in response.text:
                    results['cms'] = 'WordPress'
                elif 'Joomla' in response.text:
                    results['cms'] = 'Joomla'
                elif 'Drupal' in response.text:
                    results['cms'] = 'Drupal'
                
                # Check for JavaScript frameworks
                if 'react' in response.text.lower():
                    results['js_framework'] = 'React'
                elif 'angular' in response.text.lower():
                    results['js_framework'] = 'Angular'
                elif 'vue' in response.text.lower():
                    results['js_framework'] = 'Vue.js'
                
                # Check for admin panels
                admin_patterns = ['/admin', '/login', '/wp-admin', '/administrator']
                for pattern in admin_patterns:
                    if pattern in response.text or url + pattern:
                        if 'admin_panels' not in results:
                            results['admin_panels'] = []
                        results['admin_panels'].append(pattern)
                        
            except:
                pass
                
        return results
