# ddos_defense_service.py
import time
import logging
import threading
import signal
import sys
import pickle
import os
from typing import Dict, List, Set

# Import custom modules
from src.packet_capture import PacketCapture
from src.feature_extractor import FeatureExtractor
from src.ddos_detector import DDoSDetector
from src.firewall_manager import FirewallManager
from src.alert_system import AlertSystem
from src.behavior_analyzer import BehaviorAnalyzer

# Import configuration
import config

# Set up logging
logging.basicConfig(
    filename='logs/ddos_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# Add console handler for important messages
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger('').addHandler(console)

class DDoSDefenseService:
    def __init__(self):
        """Initialize the DDoS Defense Service"""
        logging.info("Initializing DDoS Defense Service")
        
        # Create components
        self.packet_capture = PacketCapture(sample_interval=config.SAMPLE_INTERVAL)
        self.feature_extractor = FeatureExtractor(model_path=self.model_path)
        self.detector = DDoSDetector(
            model_path=self.model_path,
            detection_threshold=config.DETECTION_THRESHOLD,
            attack_count_threshold=config.ATTACK_COUNT_THRESHOLD
        )
        self.firewall = FirewallManager(block_duration=config.BLOCK_DURATION)
        self.alert_system = AlertSystem(
            enable_email=config.ENABLE_EMAIL_ALERTS,
            # enable_webhook=config.ENABLE_WEBHOOK_ALERTS,
            email_config=config.EMAIL_CONFIG,
            # webhook_url=config.WEBHOOK_URL
        )
        # Thêm behavior analyzer
        self.behavior_analyzer = BehaviorAnalyzer(window_size=3600)
    
    def start(self):
        """Start the DDoS Defense Service"""
        if self.running:
            logging.warning("Service already running")
            return
        
        self.running = True
        
        # Start packet capture
        self.packet_capture.start_capture()
        
        # Start detection loop in a separate thread
        self.detection_thread = threading.Thread(target=self.detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        
        logging.info("DDoS Defense Service started")
    
    def stop(self):
        """Stop the DDoS Defense Service"""
        if not self.running:
            return
        
        self.running = False
        
        # Stop packet capture
        self.packet_capture.stop_capture()
        
        # Wait for detection thread to finish
        if self.detection_thread and self.detection_thread.is_alive():
            self.detection_thread.join(timeout=5)
        
        # Clean up firewall rules
        self.firewall.cleanup()
        
        logging.info("DDoS Defense Service stopped")
    
    def detection_loop(self):
        """Main detection loop"""
        while self.running:
            try:
                # Get flow features
                flow_data = self.packet_capture.get_flow_features()
                
                if not flow_data:
                    time.sleep(1)
                    continue
                
                # Extract features
                features_df = self.feature_extractor.extract_features(flow_data)
                
                if features_df.empty:
                    time.sleep(1)
                    continue
                
                # Detect DDoS attacks
                detection_results, ips_to_block = self.detector.detect(features_df)
                
                # Process detection results
                self._process_detection_results(detection_results)
                
                # Block IPs if auto-block is enabled
                if config.ENABLE_AUTO_BLOCK and ips_to_block:
                    self.firewall.block_ips(ips_to_block)
                    
                    # Send alerts for blocked IPs
                    for ip in ips_to_block:
                        self.alert_system.send_alert(
                            'blocked',
                            {
                                'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                                'src_ip': ip,
                                'count': self.detector.suspicious_ips[ip]['count'],
                                'attack_types': list(self.detector.suspicious_ips[ip]['attack_types'])
                            }
                        )
                
                # Unblock expired IPs
                self.firewall.unblock_expired()
                
                # Sleep for the configured interval
                time.sleep(config.SAMPLE_INTERVAL)
                
            except Exception as e:
                logging.error(f"Error in detection loop: {str(e)}")
                time.sleep(1)
    
    def _process_detection_results(self, detection_results):
        """Process detection results and send alerts"""
        for result in detection_results:
            if result['is_attack']:
                # Log the attack
                attack_info = {
                    'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': result['src_ip'],
                    'dst_ip': result['dst_ip'],
                    'attack_type': result['attack_type'],
                    'confidence': result['confidence']
                }
                
                # Send alert for high-confidence attacks
                if result['confidence'] > 0.9:
                    self.alert_system.send_alert('detected', attack_info)
    
    def signal_handler(self, sig, frame):
        """Handle termination signals"""
        logging.info(f"Received signal {sig}, shutting down")
        self.stop()
        sys.exit(0)
    
    def get_status(self):
        """Get the current status of the service"""
        return {
            'running': self.running,
            'blocked_ips': self.firewall.get_blocked_ips(),
            'suspicious_ips': len(self.detector.suspicious_ips)
        }


# API for service control and monitoring
from flask import Flask, jsonify, request, abort
import threading

app = Flask(__name__)
service = None
# app.config['SECRET_KEY'] = config.API_SECRET_KEY

def require_api_key(f):
    """Decorator không thực hiện xác thực"""
    return f  # Chỉ trả về hàm nguyên bản, không thêm xác thực

@app.route('/api/status', methods=['GET'])
# @require_api_key 
def get_status():
    """Get service status"""
    if not service:
        return jsonify({'error': 'Service not initialized'}), 500
    
    return jsonify(service.get_status())

@app.route('/api/blocked', methods=['GET'])
# @require_api_key  
def get_blocked():
    """Get list of blocked IPs"""
    if not service:
        return jsonify({'error': 'Service not initialized'}), 500
    
    return jsonify({'blocked_ips': service.firewall.get_blocked_ips()})

@app.route('/api/unblock/<ip>', methods=['POST'])
# @require_api_key  # Comment hoặc xóa dòng này
def unblock_ip(ip):
    """Manually unblock an IP"""
    if not service:
        return jsonify({'error': 'Service not initialized'}), 500
    
    if ip in service.firewall.blocked_ips:
        try:
            # Create a temporary set with just this IP
            service.firewall.blocked_ips[ip] = 0  # Set to unblock immediately
            service.firewall.unblock_expired()
            return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({'success': False, 'error': 'IP not in block list'}), 404

@app.route('/api/block/<ip>', methods=['POST'])
# @require_api_key  # Comment hoặc xóa dòng này
def block_ip(ip):
    """Manually block an IP"""
    if not service:
        return jsonify({'error': 'Service not initialized'}), 500
    
    try:
        service.firewall.block_ips({ip})
        return jsonify({'success': True, 'message': f'IP {ip} blocked'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def start_api_server():
    """Start the API server"""
    app.run(host=config.API_HOST, port=config.API_PORT)

# Main entry point
if __name__ == '__main__':
    # Create and start the service
    service = DDoSDefenseService()
    service.start()
    
    # Start API server in a separate thread
    api_thread = threading.Thread(target=start_api_server)
    api_thread.daemon = True
    api_thread.start()
    
    # Keep the main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        service.stop()
