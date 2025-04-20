# config.py
import os

# System Configuration
SAMPLE_INTERVAL = 5  # Seconds between feature extraction and detection runs
PACKET_CAPTURE_INTERFACE = "any"  # Network interface to monitor

# Detection Settings
MODEL_PATH = os.path.join('models', 'random_forest_model.pkl')
DETECTION_THRESHOLD = 0.7  # Probability threshold for classifying an attack
ATTACK_COUNT_THRESHOLD = 5  # Number of detections before blocking an IP

# Firewall Settings
BLOCK_DURATION = 3600  # Block IPs for 1 hour (in seconds)
ENABLE_AUTO_BLOCK = True  # Automatically block detected attackers

# Alert Settings
ENABLE_EMAIL_ALERTS = False
ENABLE_WEBHOOK_ALERTS = False

EMAIL_CONFIG = {
    'server': 'smtp.example.com',
    'port': 587,
    'use_tls': True,
    'username': 'alerts@example.com',
    'password': 'your_password',
    'recipient': 'admin@example.com'
}

WEBHOOK_URL = 'https://example.com/webhook/ddos-alerts'

# API Settings
API_HOST = '127.0.0.1'
API_PORT = 5000
# API_SECRET_KEY = 'change_this_to_a_secure_random_string'