# src/ddos_detector.py
import joblib
import logging
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Set
import time

class DDoSDetector:
    def __init__(self, model_path: str = config.MODEL_PATH,
                 detection_threshold: float = config.DETECTION_THRESHOLD,
                 attack_count_threshold: int = config.ATTACK_COUNT_THRESHOLD):
        
        self.model_data = joblib.load(model_path)
        self.model = (self.model_data.get('model') 
                     if isinstance(self.model_data, dict) 
                     else self.model_data)
        
        self.detection_threshold = detection_threshold
        self.attack_count_threshold = attack_count_threshold
        self.suspicious_ips = {}
        
        # Attack signature database
        self.attack_signatures = {
            'LOIC': {
                'http_rate': 100,
                'syn_rate': 50,
                'packet_uniformity': 0.9
            },
            'HOIC': {
                'http_rate': 1000,
                'connection_rate': 100,
                'entropy_threshold': 0.6
            },
            'UDP_FLOOD': {
                'udp_rate': 1000,
                'packet_size': 65000
            },
            'SYN_FLOOD': {
                'syn_rate': 100,
                'ack_ratio': 0.1
            },
            'SLOWLORIS': {
                'connection_duration': 900,
                'incomplete_ratio': 0.8
            },
            'HTTP_FLOOD': {
                'request_rate': 100,
                'error_rate': 0.3
            }
        }
    
    def detect(self, features_df) -> Tuple[List[Dict], Set[str]]:
        if features_df.empty:
            return [], set()
        
        try:
            results = []
            ips_to_block = set()
            current_time = time.time()
            
            # ML-based detection
            predictions_proba = self.model.predict_proba(features_df)
            predictions = self.model.predict(features_df)
            
            # Process each flow
            for i, row in features_df.iterrows():
                src_ip = row.get('src_ip', 'unknown')
                attack_types = set()
                confidence_scores = {}
                
                # 1. Check ML prediction
                ml_confidence = max(predictions_proba[i])
                if ml_confidence > self.detection_threshold:
                    attack_types.add(f"ML_DETECTED_{predictions[i]}")
                    confidence_scores['ML'] = ml_confidence
                
                # 2. Check LOIC signatures
                if (row.get('packets_per_second', 0) > self.attack_signatures['LOIC']['http_rate'] and
                    row.get('Flag SYN', 0) > self.attack_signatures['LOIC']['syn_rate']):
                    attack_types.add('LOIC_ATTACK')
                    confidence_scores['LOIC'] = 0.9
                
                # 3. Check HOIC signatures
                if (row.get('packets_per_second', 0) > self.attack_signatures['HOIC']['http_rate'] and
                    row.get('packet_size_entropy', 1) < self.attack_signatures['HOIC']['entropy_threshold']):
                    attack_types.add('HOIC_ATTACK')
                    confidence_scores['HOIC'] = 0.95
                
                # 4. Check SYN Flood
                syn_ack_ratio = (row.get('Flag SYN', 0) / 
                               (row.get('Flag ACK', 1) or 1))  # Avoid division by zero
                if syn_ack_ratio > 10:
                    attack_types.add('SYN_FLOOD')
                    confidence_scores['SYN_FLOOD'] = min(syn_ack_ratio / 20, 0.99)
                
                # 5. Check UDP Flood
                if row.get('Protocol') == 17 and row.get('bytes_per_second', 0) > 1000000:
                    attack_types.add('UDP_FLOOD')
                    confidence_scores['UDP_FLOOD'] = 0.9
                
                # 6. Check HTTP Flood patterns
                if (row.get('packets_per_second', 0) > 100 and 
                    row.get('Flag PSH', 0) > 50):
                    attack_types.add('HTTP_FLOOD')
                    confidence_scores['HTTP_FLOOD'] = 0.85
                
                # 7. Check for pattern-based attacks
                packet_size_cv = (row.get('packet_size_std', 0) / 
                                (row.get('packet_size_mean', 1) or 1))
                if packet_size_cv < 0.1:
                    attack_types.add('AUTOMATED_TOOL_ATTACK')
                    confidence_scores['AUTOMATED'] = 0.8
                
                # If any attack detected
                if attack_types:
                    # Get highest confidence score
                    max_confidence = max(confidence_scores.values())
                    
                    # Create result
                    result = {
                        'src_ip': src_ip,
                        'dst_ip': row.get('dst_ip', 'unknown'),
                        'attack_types': list(attack_types),
                        'confidence': max_confidence,
                        'is_attack': True,
                        'metrics': {
                            'packets_per_second': row.get('packets_per_second', 0),
                            'bytes_per_second': row.get('bytes_per_second', 0),
                            'syn_count': row.get('Flag SYN', 0),
                            'entropy': row.get('packet_size_entropy', 0)
                        }
                    }
                    
                    results.append(result)
                    
                    # Update suspicious IPs tracking
                    if src_ip not in self.suspicious_ips:
                        self.suspicious_ips[src_ip] = {
                            'count': 0,
                            'first_seen': current_time,
                            'last_seen': current_time,
                            'attack_types': set()
                        }
                    
                    record = self.suspicious_ips[src_ip]
                    record['count'] += 1
                    record['last_seen'] = current_time
                    record['attack_types'].update(attack_types)
                    
                    # Check if should block
                    if record['count'] >= self.attack_count_threshold:
                        ips_to_block.add(src_ip)
                        logging.warning(
                            f"Attack detected from {src_ip}. "
                            f"Types: {attack_types}, "
                            f"Confidence: {max_confidence:.2f}, "
                            f"Count: {record['count']}"
                        )
                    
                    behavior_analysis = self.behavior_analyzer.analyze(
                        ip=src_ip,
                        current_stats={
                            'packets_per_second': row.get('packets_per_second', 0),
                            'bytes_per_second': row.get('bytes_per_second', 0),
                            'tcp_flags': {
                                'SYN': row.get('Flag SYN', 0),
                                'ACK': row.get('Flag ACK', 0),
                                'RST': row.get('Flag RST', 0),
                                'FIN': row.get('Flag FIN', 0)
                            }
                        }
                    )
                    
                    # Nếu phát hiện hành vi đáng ngờ
                    if behavior_analysis['behavioral_score'] > 0.8:
                        attack_types.add('BEHAVIORAL_ANOMALY')
                        confidence_scores['BEHAVIORAL'] = behavior_analysis['behavioral_score']
                    
                    # Nếu phát hiện mẫu tấn công đã biết
                    if behavior_analysis['pattern_match']:
                        for pattern in behavior_analysis['pattern_match']:
                            attack_types.add(f'PATTERN_{pattern}')
                            confidence_scores['PATTERN'] = 0.9

                    
            
            # Cleanup old records
            self._cleanup_old_records(current_time - 3600)
            
            return results, ips_to_block
            
        except Exception as e:
            logging.error(f"Error in detect method: {str(e)}")
            return [], set()

    def _detect_amplification_attack(self, flow_stats: Dict) -> Tuple[bool, str, float]:
        """Detect amplification attacks"""
        if flow_stats['Protocol'] == 17:  # UDP
            response_size = flow_stats.get('packet_size_mean', 0)
            packet_rate = flow_stats.get('packets_per_second', 0)
            
            # DNS Amplification
            if flow_stats.get('dst_port') == 53 and response_size > 512:
                return True, 'DNS_AMPLIFICATION', 0.9
            
            # NTP Amplification
            if flow_stats.get('dst_port') == 123 and response_size > 1000:
                return True, 'NTP_AMPLIFICATION', 0.95
            
            # SSDP Amplification
            if flow_stats.get('dst_port') == 1900 and packet_rate > 100:
                return True, 'SSDP_AMPLIFICATION', 0.85
        
        return False, '', 0.0

    def _detect_slowloris(self, flow_stats: Dict) -> Tuple[bool, float]:
        """Detect Slowloris attacks"""
        if flow_stats['Protocol'] == 6:  # TCP
            connection_duration = flow_stats.get('Flow Duration', 0)
            incomplete_ratio = (
                flow_stats.get('Flag SYN', 0) - 
                flow_stats.get('Flag ACK', 0)
            ) / max(flow_stats.get('Flag SYN', 1), 1)
            
            if (connection_duration > 900 and  # 15 minutes
                incomplete_ratio > 0.8):
                return True, 0.9
        
        return False, 0.0

    def _detect_tcp_abuse(self, flow_stats: Dict) -> List[Tuple[str, float]]:
        """Detect various TCP-based attacks"""
        attacks = []
        
        if flow_stats['Protocol'] == 6:
            # ACK Flood
            ack_rate = flow_stats.get('Flag ACK', 0) / max(flow_stats.get('Flow Duration', 1), 1)
            if ack_rate > 1000:
                attacks.append(('ACK_FLOOD', 0.85))
            
            # RST Flood
            rst_rate = flow_stats.get('Flag RST', 0) / max(flow_stats.get('Flow Duration', 1), 1)
            if rst_rate > 100:
                attacks.append(('RST_FLOOD', 0.9))
            
            # FIN Flood
            fin_rate = flow_stats.get('Flag FIN', 0) / max(flow_stats.get('Flow Duration', 1), 1)
            if fin_rate > 100:
                attacks.append(('FIN_FLOOD', 0.9))
        
        return attacks
    
    def _cleanup_old_records(self, cutoff_time: float):
        """Remove tracking for IPs not seen since cutoff_time"""
        for ip in list(self.suspicious_ips.keys()):
            if self.suspicious_ips[ip]['last_seen'] < cutoff_time:
                del self.suspicious_ips[ip]