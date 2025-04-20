# src/alert_system.py
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from typing import Dict, List, Optional
import json
import os

class AlertSystem:
    def __init__(self, 
                 enable_email: bool = False, 
                 enable_webhook: bool = False,
                 email_config: Optional[Dict] = None, 
                 webhook_url: Optional[str] = None):
        """
        Initialize the alert system
        
        Args:
            enable_email: Whether to enable email alerts
            enable_webhook: Whether to enable webhook alerts
            email_config: Email configuration (server, port, username, password)
            webhook_url: URL for webhook alerts
        """
        self.enable_email = enable_email
        self.enable_webhook = enable_webhook
        self.email_config = email_config
        self.webhook_url = webhook_url
        
        # Ensure log directory exists
        os.makedirs('logs', exist_ok=True)
        
        # Set up the logger for alerts
        self.alert_logger = logging.getLogger('ddos_alerts')
        self.alert_logger.setLevel(logging.WARNING)
        
        # Add a file handler
        alert_handler = logging.FileHandler('logs/ddos_alerts.log')
        alert_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.alert_logger.addHandler(alert_handler)
    
    def send_alert(self, alert_type: str, details: Dict) -> bool:
        """
        Send an alert about a DDoS attack
        
        Args:
            alert_type: Type of alert (e.g., 'detected', 'blocked')
            details: Dictionary with alert details
            
        Returns:
            Boolean indicating success
        """
        message = f"DDoS {alert_type}: {json.dumps(details, indent=2)}"
        
        # Log the alert
        self.alert_logger.warning(message)
        
        # Send email alert
        email_sent = False
        if self.enable_email and self.email_config:
            email_sent = self._send_email_alert(alert_type, details)
        
        # Send webhook alert
        webhook_sent = False
        if self.enable_webhook and self.webhook_url:
            webhook_sent = self._send_webhook_alert(alert_type, details)
        
        return email_sent or webhook_sent
    
    def _send_email_alert(self, alert_type: str, details: Dict) -> bool:
        """Send an email alert"""
        try:
            subject = f"DDoS Alert: {alert_type.capitalize()}"
            
            # Create message body
            body = f"DDoS {alert_type.upper()} ALERT\n\n"
            body += f"Time: {details.get('time', 'Unknown')}\n"
            
            if 'src_ip' in details:
                body += f"Source IP: {details['src_ip']}\n"
            
            if 'attack_type' in details:
                body += f"Attack Type: {details['attack_type']}\n"
            
            if 'confidence' in details:
                body += f"Confidence: {details['confidence']:.2f}\n"
            
            if 'count' in details:
                body += f"Attack Count: {details['count']}\n"
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = self.email_config.get('username', 'ddos-defense@system')
            msg['To'] = self.email_config.get('recipient', 'admin@system')
            
            # Connect to server and send
            with smtplib.SMTP(self.email_config['server'], self.email_config['port']) as server:
                if self.email_config.get('use_tls', True):
                    server.starttls()
                
                if 'username' in self.email_config and 'password' in self.email_config:
                    server.login(self.email_config['username'], self.email_config['password'])
                
                server.send_message(msg)
            
            logging.info(f"Email alert sent for {alert_type}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {str(e)}")
            return False
    
    def _send_webhook_alert(self, alert_type: str, details: Dict) -> bool:
        """Send a webhook alert"""
        try:
            payload = {
                'alert_type': alert_type,
                'details': details
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            
            if response.status_code < 400:
                logging.info(f"Webhook alert sent for {alert_type}")
                return True
            else:
                logging.error(f"Webhook returned error {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            logging.error(f"Failed to send webhook alert: {str(e)}")
            return False