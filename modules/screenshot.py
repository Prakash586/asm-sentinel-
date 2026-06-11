import os
import time
from datetime import datetime
from typing import Dict, List
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import hashlib

class ScreenshotCapture:
    def __init__(self, screenshot_dir: str = "screenshots"):
        self.screenshot_dir = screenshot_dir
        os.makedirs(screenshot_dir, exist_ok=True)
        self.setup_driver()
        
    def setup_driver(self):
        """Setup headless Chrome driver"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--window-size=1920,1080')
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
        except:
            print("[!] Chrome driver not found, screenshot functionality disabled")
            self.driver = None
            
    def capture(self, url: str) -> Dict:
        """Capture screenshot of a URL"""
        result = {
            'url': url,
            'success': False,
            'path': None,
            'hash': None,
            'error': None
        }
        
        if not self.driver:
            result['error'] = "Driver not available"
            return result
            
        try:
            self.driver.get(url)
            time.sleep(2)  # Wait for page to load
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = hashlib.md5(url.encode()).hexdigest()
            daily_dir = os.path.join(self.screenshot_dir, datetime.now().strftime('%Y-%m-%d'))
            os.makedirs(daily_dir, exist_ok=True)
            
            filepath = os.path.join(daily_dir, f"{filename}_{timestamp}.png")
            self.driver.save_screenshot(filepath)
            
            # Calculate hash for change detection
            with open(filepath, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            
            result['success'] = True
            result['path'] = filepath
            result['hash'] = file_hash
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def detect_changes(self, url: str, current_hash: str, previous_hash: str) -> bool:
        """Detect visual changes in screenshots"""
        return current_hash != previous_hash
    
    def cleanup_old_screenshots(self, days: int = 30):
        """Remove screenshots older than specified days"""
        cutoff = time.time() - (days * 86400)
        
        for root, dirs, files in os.walk(self.screenshot_dir):
            for file in files:
                filepath = os.path.join(root, file)
                if os.path.getmtime(filepath) < cutoff:
                    os.remove(filepath)
                    print(f"[+] Removed old screenshot: {filepath}")
