# modules/__init__.py

from .asset_discovery import AssetDiscovery
from .dns_monitor import DNSMonitor
from .port_scanner import PortScanner
from .tech_detection import TechDetector
from .ssl_monitor import SSLMonitor
from .screenshot import ScreenshotCapture
from .cloud_assets import CloudScanner
from .vuln_lookup import VulnLookup
from .risk_scoring import RiskScorer
from .db_manager import DatabaseManager      # ← Add this line

__all__ = [
    'AssetDiscovery',
    'DNSMonitor', 
    'PortScanner',
    'TechDetector',
    'SSLMonitor',
    'ScreenshotCapture',
    'CloudScanner',
    'VulnLookup',
    'RiskScorer',
    'DatabaseManager'                         # ← Add this
]
