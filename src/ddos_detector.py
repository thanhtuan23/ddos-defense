# src/ddos_detector.py
import pandas as pd
import numpy as np
import joblib
import logging
from typing import Dict, List, Tuple, Set
import time

class DDoSDetector:
    def __init__(self, model_path: str = 'models/random_forest_model.pkl', 
                 detection_threshold: float = 0.8,
                 attack_count_threshold: int = 5):
        """
        Initialize the DDoS detector with a model
        
        Args:
            model_path: Path to the saved model file
            detection_threshold: Probability threshold for classification
            attack_count_threshold: Number of detected attacks before blocking
        """
        # Load the model
        model_data = joblib.load(model_path)
        self.model = model_data.get('model')
        self.label_encoder = model_data.get('label_encoder')
        
        self.detection_threshold = detection_threshold
        self.attack_count_threshold = attack_count_threshold
        self.suspicious_ips = {}  # IP -> {count, first_seen, last_seen, attack_types}
        
        logging.info(f"DDoS detector initialized with model from {model_path}")
    
    def detect(self, features_df: pd.DataFrame) -> Tuple[List[Dict], Set[str]]:
        """
        Detect DDoS attacks in the provided features
        
        Args:
            features_df: DataFrame containing extracted features
            
        Returns:
            Tuple of (detection_results, ips_to_block)
        """
        if features_df.empty:
            return [], set()
        
        # Save IP addresses
        ip_addresses = None
        if 'src_ip' in features_df.columns and 'dst_ip' in features_df.columns:
            ip_addresses = features_df[['src_ip', 'dst_ip']].copy()
            features_df = features_df.drop(['src_ip', 'dst_ip'], axis=1)
        
        # Run prediction
        predictions_proba = self.model.predict_proba(features_df)
        predictions = self.model.predict(features_df)
        
        # Decode class labels
        attack_labels = [self.label_encoder.inverse_transform([p])[0] for p in predictions]
        
        # Prepare results
        results = []
        ips_to_block = set()
        
        current_time = time.time()
        
        for i in range(len(predictions)):
            if ip_addresses is not None:
                src_ip = ip_addresses.iloc[i]['src_ip']
                dst_ip = ip_addresses.iloc[i]['dst_ip']
            else:
                src_ip = "unknown"
                dst_ip = "unknown"
            
            attack_type = attack_labels[i]
            max_probability = max(predictions_proba[i])
            
            # Only consider as attack if not benign and above threshold
            is_attack = attack_type != 'Benign' and max_probability >= self.detection_threshold
            
            result = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'attack_type': attack_type,
                'confidence': max_probability,
                'is_attack': is_attack
            }
            
            results.append(result)
            
            # Track suspicious IPs
            if is_attack:
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
                record['attack_types'].add(attack_type)
                
                # Log the detection
                logging.warning(
                    f"Potential {attack_type} attack detected from {src_ip} to {dst_ip} "
                    f"with {max_probability:.2f} confidence (count: {record['count']})"
                )
                
                # Check if we should block
                if record['count'] >= self.attack_count_threshold:
                    ips_to_block.add(src_ip)
                    logging.warning(f"IP {src_ip} exceeded threshold with {record['count']} attacks. Marked for blocking.")
        
        # Clean up old records (older than 1 hour)
        self._cleanup_old_records(current_time - 3600)
        
        return results, ips_to_block
    
    def _cleanup_old_records(self, cutoff_time: float):
        """Remove tracking for IPs not seen since cutoff_time"""
        for ip in list(self.suspicious_ips.keys()):
            if self.suspicious_ips[ip]['last_seen'] < cutoff_time:
                del self.suspicious_ips[ip]