# src/packet_capture.py
import time
import socket
import struct
import threading
from collections import defaultdict, Counter
import logging
import math
import numpy as np
from typing import Dict, List, Set, DefaultDict
import config

class PacketAnalyzer:
    """Helper class for analyzing packet patterns"""
    
    @staticmethod
    def calculate_entropy(data: List) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        counter = Counter(data)
        prob = [count/len(data) for count in counter.values()]
        return -sum(p * math.log2(p) for p in prob)
    
    @staticmethod
    def calculate_statistics(data: List) -> Dict:
        """Calculate basic statistics of data"""
        if not data:
            return {'mean': 0, 'std': 0, 'cv': 0}
        mean = np.mean(data)
        std = np.std(data)
        cv = std/mean if mean != 0 else 0
        return {'mean': mean, 'std': std, 'cv': cv}

class FlowTracker:
    """Track flow statistics"""
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.reset()
    
    def reset(self):
        self.packet_counts = []
        self.byte_counts = []
        self.timestamps = []
        self.packet_sizes = []
        self.inter_arrival_times = []
        self.tcp_flags = defaultdict(int)
        self.last_seen = time.time()
    
    def add_packet(self, size: int, timestamp: float, flags: Dict = None):
        self.packet_counts.append(1)
        self.byte_counts.append(size)
        self.packet_sizes.append(size)
        self.timestamps.append(timestamp)
        
        if len(self.timestamps) > 1:
            iat = self.timestamps[-1] - self.timestamps[-2]
            self.inter_arrival_times.append(iat)
        
        if flags:
            for flag, value in flags.items():
                self.tcp_flags[flag] += value
        
        self.last_seen = timestamp
        self._cleanup(timestamp)
    
    def _cleanup(self, current_time: float):
        """Remove old data outside the window"""
        cutoff = current_time - self.window_size
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.pop(0)
            self.packet_counts.pop(0)
            self.byte_counts.pop(0)
            if self.inter_arrival_times:
                self.inter_arrival_times.pop(0)
    
    def get_statistics(self) -> Dict:
        """Get current statistics"""
        current_time = time.time()
        self._cleanup(current_time)
        
        if not self.timestamps:
            return self._empty_stats()
        
        window = current_time - self.timestamps[0]
        if window <= 0:
            return self._empty_stats()
        
        stats = {
            'packets_per_second': len(self.packet_counts) / window,
            'bytes_per_second': sum(self.byte_counts) / window,
            'packet_size_stats': PacketAnalyzer.calculate_statistics(self.packet_sizes),
            'iat_stats': PacketAnalyzer.calculate_statistics(self.inter_arrival_times),
            'tcp_flags': dict(self.tcp_flags),
            'entropy': PacketAnalyzer.calculate_entropy(self.packet_sizes)
        }
        
        return stats
    
    def _empty_stats(self) -> Dict:
        return {
            'packets_per_second': 0,
            'bytes_per_second': 0,
            'packet_size_stats': {'mean': 0, 'std': 0, 'cv': 0},
            'iat_stats': {'mean': 0, 'std': 0, 'cv': 0},
            'tcp_flags': {},
            'entropy': 0
        }

class PacketCapture:
    def __init__(self, sample_interval: int = config.SAMPLE_INTERVAL):
        self.sample_interval = sample_interval
        self.raw_socket = None
        self.running = False
        self.lock = threading.Lock()
        
        # Tracking different time windows
        self.flows = defaultdict(lambda: {
            'short': FlowTracker(config.TIME_WINDOWS['SHORT']),
            'medium': FlowTracker(config.TIME_WINDOWS['MEDIUM']),
            'long': FlowTracker(config.TIME_WINDOWS['LONG'])
        })
        
        # Protocol specific tracking
        self.http_tracker = defaultdict(lambda: {
            'requests': 0,
            'errors': 0,
            'methods': Counter(),
            'urls': Counter(),
            'user_agents': Counter(),
            'last_reset': time.time()
        })
        
        self.attack_patterns = defaultdict(lambda: {
            'last_detection': time.time(),
            'detection_count': 0,
            'attack_types': set()
        })
    
    def start_capture(self):
        """Start packet capturing in a separate thread"""
        self.running = True
        
        try:
            # Interface "any" bắt tất cả gói tin
            if config.PACKET_CAPTURE_INTERFACE == "any":
                self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            else:
                # Tạo socket cho interface cụ thể
                self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                self.raw_socket.bind((config.PACKET_CAPTURE_INTERFACE, 0))
            
            capture_thread = threading.Thread(target=self._capture_packets)
            capture_thread.daemon = True
            capture_thread.start()
            
            logging.info(f"Packet capture started on interface {config.PACKET_CAPTURE_INTERFACE}")
        except Exception as e:
            logging.error(f"Failed to start capture: {str(e)}")
            logging.exception(e)

    def _process_packet(self, packet_data: bytes):
        try:
            # Parse Ethernet header
            eth_header = packet_data[:14]
            eth_protocol = socket.ntohs(struct.unpack('!H', eth_header[12:14])[0])
            
            if eth_protocol != 0x0800:  # Not IP
                return
            
            # Parse IP header
            ip_header = packet_data[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            ip_header_length = ihl * 4
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            
            current_time = time.time()
            packet_size = len(packet_data)
            
            # Skip whitelisted IPs
            if s_addr in config.PROTECTION_SETTINGS['WHITELIST']:
                return
            
            # Process based on protocol
            if protocol == 6:  # TCP
                self._process_tcp_packet(packet_data, ip_header_length, s_addr, d_addr, 
                                      current_time, packet_size)
            elif protocol == 17:  # UDP
                self._process_udp_packet(packet_data, ip_header_length, s_addr, d_addr,
                                      current_time, packet_size)
            elif protocol == 1:  # ICMP
                self._process_icmp_packet(s_addr, d_addr, current_time, packet_size)
            
            # Update flow statistics
            flow_key = f"{s_addr}_{d_addr}_{protocol}"
            with self.lock:
                for window in ['short', 'medium', 'long']:
                    self.flows[flow_key][window].add_packet(packet_size, current_time)
            
            # Check for attacks
            self._check_attack_patterns(s_addr, d_addr, protocol, current_time)
            
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")
    
    def _process_tcp_packet(self, packet_data, ip_header_length, s_addr, d_addr, 
                          current_time, packet_size):
        try:
            tcp_header_offset = 14 + ip_header_length
            tcp_header = packet_data[tcp_header_offset:tcp_header_offset + 20]
            
            if len(tcp_header) >= 20:
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                source_port = tcph[0]
                dest_port = tcph[1]
                flags = tcph[5]
                
                # Extract TCP flags
                tcp_flags = {
                    'FIN': flags & 0x01,
                    'SYN': flags & 0x02,
                    'RST': flags & 0x04,
                    'PSH': flags & 0x08,
                    'ACK': flags & 0x10,
                    'URG': flags & 0x20
                }
                
                # Process HTTP(S) traffic
                if dest_port in [80, 443, 8080]:
                    self._process_http_traffic(packet_data, tcp_header_offset + 20,
                                            s_addr, tcp_flags)
                
                # Update flow trackers with TCP flags
                flow_key = f"{s_addr}_{d_addr}_TCP"
                with self.lock:
                    for window in ['short', 'medium', 'long']:
                        self.flows[flow_key][window].add_packet(packet_size, current_time, tcp_flags)
                
        except Exception as e:
            logging.error(f"Error processing TCP packet: {str(e)}")
    
    def _process_udp_packet(self, packet_data, ip_header_length, s_addr, d_addr,
                          current_time, packet_size):
        try:
            udp_header_offset = 14 + ip_header_length
            udp_header = packet_data[udp_header_offset:udp_header_offset + 8]
            
            if len(udp_header) >= 8:
                udph = struct.unpack('!HHHH', udp_header)
                source_port = udph[0]
                dest_port = udph[1]
                
                # Update UDP specific tracking
                flow_key = f"{s_addr}_{d_addr}_UDP"
                with self.lock:
                    for window in ['short', 'medium', 'long']:
                        self.flows[flow_key][window].add_packet(packet_size, current_time)
                
        except Exception as e:
            logging.error(f"Error processing UDP packet: {str(e)}")
    
    def _process_icmp_packet(self, s_addr, d_addr, current_time, packet_size):
        try:
            # Update ICMP specific tracking
            flow_key = f"{s_addr}_{d_addr}_ICMP"
            with self.lock:
                for window in ['short', 'medium', 'long']:
                    self.flows[flow_key][window].add_packet(packet_size, current_time)
                    
        except Exception as e:
            logging.error(f"Error processing ICMP packet: {str(e)}")
    
    def _process_http_traffic(self, packet_data, payload_offset, s_addr, tcp_flags):
        try:
            if len(packet_data) <= payload_offset:
                return
            
            payload = packet_data[payload_offset:]
            
            # Basic HTTP request detection
            with self.lock:
                tracker = self.http_tracker[s_addr]
                current_time = time.time()
                
                # Reset counters if interval passed
                if current_time - tracker['last_reset'] > self.sample_interval:
                    tracker['requests'] = 0
                    tracker['errors'] = 0
                    tracker['last_reset'] = current_time
                
                # Update counters
                if tcp_flags['SYN']:
                    tracker['requests'] += 1
                
                if tcp_flags['RST'] or tcp_flags['FIN']:
                    tracker['errors'] += 1
                
        except Exception as e:
            logging.error(f"Error processing HTTP traffic: {str(e)}")
    
    def _check_attack_patterns(self, s_addr, d_addr, protocol, current_time):
        try:
            flow_key = f"{s_addr}_{d_addr}_{protocol}"
            attack_types = set()
            
            with self.lock:
                # Get flow statistics
                flow_stats = self.flows[flow_key]['short'].get_statistics()
                
                # Check various attack patterns
                # 1. High packet rate
                if flow_stats['packets_per_second'] > config.DDOS_THRESHOLDS['PACKETS_PER_SECOND']:
                    attack_types.add('HIGH_PACKET_RATE')
                
                # 2. High byte rate
                if flow_stats['bytes_per_second'] > config.DDOS_THRESHOLDS['BYTES_PER_SECOND']:
                    attack_types.add('HIGH_BYTE_RATE')
                
                # 3. TCP specific checks
                if protocol == 6:
                    tcp_flags = flow_stats['tcp_flags']
                    if tcp_flags.get('SYN', 0) > config.DDOS_THRESHOLDS['TCP_SYN_RATE']:
                        attack_types.add('SYN_FLOOD')
                
                # 4. HTTP specific checks
                if s_addr in self.http_tracker:
                    http_stats = self.http_tracker[s_addr]
                    if http_stats['requests'] > config.DDOS_THRESHOLDS['HTTP_REQUESTS_PER_SECOND']:
                        attack_types.add('HTTP_FLOOD')
                
                # 5. Pattern based detection
                if flow_stats['packet_size_stats']['cv'] < config.DDOS_THRESHOLDS['PACKET_SIZE_VARIATION']:
                    attack_types.add('UNIFORM_PATTERN')
                
                # 6. Entropy based detection
                if flow_stats['entropy'] < config.DDOS_THRESHOLDS['ENTROPY_THRESHOLD']:
                    attack_types.add('LOW_ENTROPY_ATTACK')
                
                # Update attack patterns
                if attack_types:
                    pattern = self.attack_patterns[s_addr]
                    pattern['last_detection'] = current_time
                    pattern['detection_count'] += 1
                    pattern['attack_types'].update(attack_types)
                    
                    logging.warning(
                        f"Potential attack detected from {s_addr}. "
                        f"Types: {attack_types}, "
                        f"Count: {pattern['detection_count']}"
                    )
            
        except Exception as e:
            logging.error(f"Error checking attack patterns: {str(e)}")
    
    def get_flow_features(self) -> List[Dict]:
        """Extract features from collected flow data"""
        current_time = time.time()
        result = []
        
        with self.lock:
            for flow_key, windows in self.flows.items():
                # Get statistics from different time windows
                short_stats = windows['short'].get_statistics()
                medium_stats = windows['medium'].get_statistics()
                long_stats = windows['long'].get_statistics()
                
                # Parse flow key
                s_addr, d_addr, protocol = flow_key.rsplit('_', 2)
                
                # Compile features
                features = {
                    'src_ip': s_addr,
                    'dst_ip': d_addr,
                    'Protocol': int(protocol),
                    
                    # Short-term features
                    'packets_per_second': short_stats['packets_per_second'],
                    'bytes_per_second': short_stats['bytes_per_second'],
                    'packet_size_mean': short_stats['packet_size_stats']['mean'],
                    'packet_size_std': short_stats['packet_size_stats']['std'],
                    
                    # Medium-term features
                    'med_packets_per_second': medium_stats['packets_per_second'],
                    'med_bytes_per_second': medium_stats['bytes_per_second'],
                    
                    # Long-term features
                    'long_packets_per_second': long_stats['packets_per_second'],
                    'long_bytes_per_second': long_stats['bytes_per_second'],
                    
                    # TCP flags if available
                    'Flag SYN': short_stats['tcp_flags'].get('SYN', 0),
                    'Flag ACK': short_stats['tcp_flags'].get('ACK', 0),
                    'Flag PSH': short_stats['tcp_flags'].get('PSH', 0),
                    'Flag RST': short_stats['tcp_flags'].get('RST', 0),
                    'Flag FIN': short_stats['tcp_flags'].get('FIN', 0),
                    'Flag URG': short_stats['tcp_flags'].get('URG', 0),
                    
                    # Additional features
                    'packet_size_entropy': short_stats['entropy'],
                    'iat_mean': short_stats['iat_stats']['mean'],
                    'iat_std': short_stats['iat_stats']['std']
                }
                
                result.append(features)
                
                # Cleanup old flows
                if current_time - windows['long'].last_seen > config.TIME_WINDOWS['LONG']:
                    del self.flows[flow_key]
        
        return result
    
    def stop_capture(self):
        """Stop packet capturing"""
        self.running = False
        if self.raw_socket:
            self.raw_socket.close()
        logging.info("Packet capture stopped")

    def _capture_packets(self):
        """Main packet capturing loop"""
        while self.running:
            try:
                packet_data, _ = self.raw_socket.recvfrom(65535)
                self._process_packet(packet_data)
            except Exception as e:
                if self.running:  # Only log errors if we're still supposed to be running
                    logging.error(f"Error in packet capture: {str(e)}")