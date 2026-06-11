from typing import Dict, List

class RiskScorer:
    def __init__(self, weights: Dict):
        self.weights = weights
        
    def calculate_score(self, asset: Dict) -> int:
        """Calculate risk score for an asset"""
        score = 0
        
        # Internet exposure
        if asset.get('internet_exposed', False):
            score += self.weights.get('internet_exposed', 10)
            
        # Admin panels
        if asset.get('admin_panels'):
            score += self.weights.get('admin_panels', 20) * len(asset['admin_panels'])
            
        # Outdated software
        if asset.get('outdated_software'):
            score += self.weights.get('outdated_software', 30)
            
        # SSL issues
        if asset.get('ssl_expired', False):
            score += self.weights.get('expired_ssl', 15)
        elif asset.get('ssl_expiring_soon', False):
            score += self.weights.get('expired_ssl', 15) // 2
            
        # Default login pages
        if asset.get('default_login', False):
            score += self.weights.get('default_login', 25)
            
        # Open sensitive ports
        sensitive_ports = [21, 22, 23, 3389, 5900]
        open_sensitive = [p for p in asset.get('open_ports', []) if p in sensitive_ports]
        score += len(open_sensitive) * self.weights.get('open_ports', 5)
        
        # Known vulnerabilities
        if asset.get('vulnerabilities'):
            score += self.weights.get('known_vulnerability', 40) * len(asset['vulnerabilities'])
            
        return min(score, 100)  # Cap at 100
    
    def get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
