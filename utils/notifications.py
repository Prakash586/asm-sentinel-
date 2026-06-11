import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict
from datetime import datetime

class NotificationManager:
    def __init__(self, config: Dict):
        self.config = config
        self.slack_webhook = config.get('slack_webhook')
        
    def send_slack_alert(self, message: str, color: str = "danger"):
        """Send alert to Slack"""
        if not self.slack_webhook:
            return
            
        payload = {
            "attachments": [{
                "color": color,
                "title": "ASM Sentinel Alert",
                "text": message,
                "footer": "ASM Sentinel",
                "ts": int(datetime.now().timestamp())
            }]
        }
        
        try:
            response = requests.post(self.slack_webhook, json=payload, timeout=5)
            if response.status_code != 200:
                print(f"[-] Failed to send Slack alert: {response.text}")
        except Exception as e:
            print(f"[-] Slack notification error: {e}")
            
    def send_email_alert(self, subject: str, body: str, to_emails: List[str]):
        """Send email alert"""
        if not self.config.get('email', {}).get('enabled'):
            return
            
        smtp_config = self.config['email']
        
        msg = MIMEMultipart()
        msg['From'] = smtp_config['from_addr']
        msg['To'] = ', '.join(to_emails)
        msg['Subject'] = f"[ASM Sentinel] {subject}"
        
        msg.attach(MIMEText(body, 'html'))
        
        try:
            with smtplib.SMTP(smtp_config['smtp_server'], 587) as server:
                server.starttls()
                server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(msg)
        except Exception as e:
            print(f"[-] Email notification error: {e}")
            
    def send_critical_alert(self, asset_name: str, alert_type: str, details: str):
        """Send critical alert through all configured channels"""
        message = f"⚠️ *CRITICAL ALERT*\nAsset: {asset_name}\nType: {alert_type}\nDetails: {details}"
        
        # Send to Slack
        self.send_slack_alert(message, "danger")
        
        # Send to Email if configured
        if self.config.get('email', {}).get('enabled'):
            email_body = f"""
            <h2>Critical Security Alert</h2>
            <p><strong>Asset:</strong> {asset_name}</p>
            <p><strong>Type:</strong> {alert_type}</p>
            <p><strong>Details:</strong> {details}</p>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            """
            self.send_email_alert(f"Critical: {alert_type}", email_body, self.config['email']['recipients'])
