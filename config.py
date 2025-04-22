# config.py
import os

# Cấu hình hệ thống
PACKET_CAPTURE_INTERFACE = "any"
SAMPLE_INTERVAL = 1  # 1 giây để phát hiện nhanh hơn

# Cài đặt phát hiện
MODEL_PATH = os.path.join('models', 'random_forest_model.pkl')
DETECTION_THRESHOLD = 0.5
ATTACK_COUNT_THRESHOLD = 2

# Cài đặt tường lửa
BLOCK_DURATION = 3600  # Block IPs for 1 hour (in seconds)
ENABLE_AUTO_BLOCK = True  # Automatically block detected attackers

# Ngưỡng phát hiện DDoS
DDOS_THRESHOLDS = {
    # Ngưỡng chung
    'PACKETS_PER_SECOND': 500,
    'BYTES_PER_SECOND': 1000000,  # 1MB/s
    'NEW_CONNECTIONS': 100,  # Gói SYN/giây
    
    # Cụ thể cho HTTP/HTTPS
    'HTTP_REQUESTS_PER_SECOND': 100,
    'HTTP_ERROR_RATE': 0.3,  # 30% lỗi có thể là tấn công
    
    # Cụ thể cho TCP
    'TCP_SYN_RATE': 50,
    'TCP_FLAGS_RATIO': 0.8,  # Tỷ lệ SYN so với các cờ khác
    
    # Cụ thể cho UDP
    'UDP_PACKETS_PER_SECOND': 1000,
    'UDP_BYTES_PER_SECOND': 2000000,  # 2MB/s
    
    # Cụ thể cho ICMP
    'ICMP_PACKETS_PER_SECOND': 50,
    
    # Cụ thể cho kết nối
    'CONCURRENT_CONNECTIONS': 200,
    'CONNECTION_RATE': 50,
    
    # Ngưỡng hành vi
    'ENTROPY_THRESHOLD': 0.6,
    'PACKET_SIZE_VARIATION': 0.1,
    'INTER_ARRIVAL_VARIATION': 0.1,
}

# Cửa sổ thời gian cho các kiểm tra khác nhau (tính bằng giây)
TIME_WINDOWS = {
    'SHORT': 1,    # Để phát hiện ngay lập tức
    'MEDIUM': 10,  # Để phát hiện mẫu
    'LONG': 60     # Để phân tích xu hướng
}

# Cài đặt bảo vệ
PROTECTION_SETTINGS = {
    'BLOCK_DURATION': 3600,  # 1 giờ
    'MAX_BLOCKED_IPS': 10000,
    'WHITELIST': ['127.0.0.1'],
    'BLACKLIST': [],
    'PROTECTED_PORTS': [80, 443, 8080, 22],
}

# Cài đặt cảnh báo
ALERT_SETTINGS = {
    'ENABLE_EMAIL': True,  # Bật cảnh báo qua email
    'EMAIL_SETTINGS': {  # Cấu hình email
        'SMTP_SERVER': 'smtp.example.com',
        'SMTP_PORT': 587,
        'EMAIL_ADDRESS': 'your_email@example.com',
        'EMAIL_PASSWORD': 'your_password',
        'RECIPIENTS': ['recipient1@example.com', 'recipient2@example.com']
    },
    'ENABLE_WEBHOOK': False,  # tắt
    'ALERT_INTERVAL': 300,  # 5 phút giữa các cảnh báo cho cùng một IP
    'MAX_ALERTS_PER_HOUR': 100,
}

# Behavior Analysis Settings
BEHAVIOR_SETTINGS = {
    'WINDOW_SIZE': 3600,  # 1 hour
    'MIN_SAMPLES': 10,    # Minimum samples needed for analysis
    'SCORE_THRESHOLD': 0.8,  # Threshold for behavioral anomalies
    'PATTERN_CONFIDENCE': 0.9,  # Confidence for pattern matches
}

# Update Detection Settings
DETECTION_METHODS = {
    'ML_DETECTION': True,
    'PATTERN_MATCHING': True,
    'BEHAVIORAL_ANALYSIS': True,
    'STATISTICAL_ANALYSIS': True
}


# Cài đặt API
API_HOST = '127.0.0.1'
API_PORT = 5000

# Cài đặt ghi log
LOG_SETTINGS = {
    'LOG_LEVEL': 'INFO',
    'LOG_FILE': 'logs/ddos_detection.log',
    'MAX_LOG_SIZE': 10485760,  # 10MB
    'BACKUP_COUNT': 5,
}