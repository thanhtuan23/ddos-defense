# config.py
import os
import netifaces
import logging

def get_default_interface():
    """
    Tự động phát hiện network interface chính đang được sử dụng
    Returns:
        str: Tên của interface hoặc "any" nếu không thể xác định
    """
    try:
        # Cách 1: Lấy interface của default gateway
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][1]
        
        # Cách 2: Lấy interface đầu tiên không phải loopback
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface != 'lo':  # Bỏ qua loopback
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:  # Kiểm tra có IPv4 không
                    return iface
        
        # Nếu không tìm thấy, sử dụng "any"
        return "any"
    except Exception as e:
        logging.warning(f"Could not determine default interface: {e}")
        return "any"

# Cấu hình hệ thống
PACKET_CAPTURE_INTERFACE = get_default_interface()  # Giao diện mạng để bắt gói tin
PACKET_CAPTURE_FILTER = "tcp or udp or icmp"  # Bộ lọc gói tin để bắt
SAMPLE_INTERVAL = 1  # 1 giây để phát hiện nhanh hơn

# Log interface được chọn
logging.info(f"Using network interface: {PACKET_CAPTURE_INTERFACE}")

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
    'PACKETS_PER_SECOND': 50,  # 50 gói tin/giây
    'BYTES_PER_SECOND': 10000,  # 10KB/giây
    'NEW_CONNECTIONS': 100,  # Gói SYN/giây
    
    # Cụ thể cho HTTP/HTTPS
    'HTTP_REQUESTS_PER_SECOND': 100, # 100 yêu cầu/giây
    'HTTP_ERROR_RATE': 0.3,  # 30% lỗi có thể là tấn công
    
    # Cụ thể cho TCP
    'TCP_SYN_RATE': 50, # 50 gói SYN/giây
    'TCP_FLAGS_RATIO': 0.8,  # Tỷ lệ SYN so với các cờ khác
    
    # Cụ thể cho UDP
    'UDP_PACKETS_PER_SECOND': 100, # 100 gói UDP/giây
    'UDP_BYTES_PER_SECOND': 200,  # 200 bytes/giây
    
    # Cụ thể cho ICMP
    'ICMP_PACKETS_PER_SECOND': 50, # 50 gói ICMP/giây
    
    # Cụ thể cho kết nối
    'CONCURRENT_CONNECTIONS': 200, # 200 kết nối đồng thời
    'CONNECTION_RATE': 50, # 50 kết nối mới/giây
    
    # Ngưỡng hành vi
    'ENTROPY_THRESHOLD': 0.6, # Ngưỡng entropy cho hành vi bất thường
    'PACKET_SIZE_VARIATION': 0.1, # 10% biến thể kích thước gói tin
    'INTER_ARRIVAL_VARIATION': 0.1, # 10% biến thể thời gian giữa các gói tin
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