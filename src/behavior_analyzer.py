# src/behavior_analyzer.py
import time
import numpy as np
from scipy import stats
from collections import defaultdict
from typing import Dict, List

class BehaviorAnalyzer:
    def __init__(self, window_size: int = 3600):
        self.window_size = window_size
        self.ip_history = defaultdict(lambda: {
            'packets': [],
            'bytes': [],
            'timestamps': [],
            'patterns': defaultdict(int)
        })
    
    def analyze(self, ip: str, current_stats: Dict) -> Dict:
        """Analyze behavior patterns for an IP"""
        current_time = time.time()
        history = self.ip_history[ip]
        
        # Add current statistics
        history['packets'].append(current_stats['packets_per_second'])
        history['bytes'].append(current_stats['bytes_per_second'])
        history['timestamps'].append(current_time)
        
        # Clean old data
        self._cleanup_old_data(ip, current_time)
        
        # Analyze patterns
        analysis = {
            'behavioral_score': self._calculate_behavioral_score(history),
            'pattern_match': self._match_known_patterns(history),
            'anomaly_score': self._detect_anomalies(history),
            'trend': self._analyze_trend(history)
        }
        
        return analysis
    
    def _calculate_behavioral_score(self, history: Dict) -> float:
        """Calculate a behavior score based on historical data"""
        if not history['packets']:
            return 0.0
        
        # Calculate various metrics
        packet_std = np.std(history['packets'])
        byte_std = np.std(history['bytes'])
        packet_mean = np.mean(history['packets'])
        byte_mean = np.mean(history['bytes'])
        
        # Calculate coefficient of variation
        packet_cv = packet_std / packet_mean if packet_mean > 0 else 0
        byte_cv = byte_std / byte_mean if byte_mean > 0 else 0
        
        # Combine metrics into a score
        score = 1.0 - min((packet_cv + byte_cv) / 2, 1.0)
        
        return score
    
    def _match_known_patterns(self, history: Dict) -> List[str]:
        """Match traffic patterns against known attack signatures"""
        matches = []
        
        # LOIC pattern
        if self._match_loic_pattern(history):
            matches.append('LOIC')
        
        # HOIC pattern
        if self._match_hoic_pattern(history):
            matches.append('HOIC')
        
        # Other patterns...
        
        return matches
    
    def _detect_anomalies(self, history: Dict) -> float:
        """Detect anomalies using statistical methods"""
        if len(history['packets']) < 10:
            return 0.0
        
        # Calculate z-scores
        z_scores = stats.zscore(history['packets'])
        
        # Count significant deviations
        anomalies = np.abs(z_scores) > 3
        
        return sum(anomalies) / len(anomalies)