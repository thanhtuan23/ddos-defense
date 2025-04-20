# src/packet_capture.py
import time
import socket
import struct
import threading
from collections import defaultdict
from typing import Dict, List, Tuple, DefaultDict
import logging

logging.basicConfig(
    filename='logs/ddos_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PacketCapture:
    def __init__(self, sample_interval: int = 5):
        """
        Initialize packet capture module.
        
        Args:
            sample_interval: Time window for data collection (seconds)
        """
        self.sample_interval = sample_interval
        self.raw_socket = None
        self.running = False
        self.flow_data: DefaultDict[str, Dict] = defaultdict(dict)
        self.lock = threading.Lock()
        
    def start_capture(self):
        """Start packet capturing in a separate thread"""
        self.running = True
        self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        capture_thread = threading.Thread(target=self._capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        logging.info("Packet capture started")
    
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
                logging.error(f"Error in packet capture: {str(e)}")
    
    def _process_packet(self, packet_data: bytes):
        """
        Process a captured packet and update flow statistics
        
        Args:
            packet_data: Raw packet data
        """
        # Parse Ethernet header
        eth_header = packet_data[:14]
        eth_protocol = socket.ntohs(struct.unpack('!H', eth_header[12:14])[0])
        
        # Process only IP packets (ETH_P_IP = 0x0800)
        if eth_protocol != 0x0800:
            return
            
        # Parse IP header
        ip_header = packet_data[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        protocol = iph[6]
        ip_length = (iph[0] & 0xF) * 4
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        # Create flow key (source IP, destination IP, protocol)
        flow_key = f"{s_addr}_{d_addr}_{protocol}"
        
        with self.lock:
            # Initialize flow if it doesn't exist
            if flow_key not in self.flow_data:
                self.flow_data[flow_key] = {
                    'src_ip': s_addr,
                    'dst_ip': d_addr,
                    'protocol': protocol,
                    'packet_count': 0,
                    'total_bytes': 0,
                    'start_time': time.time(),
                    'packet_sizes': [],
                    'inter_arrival_times': [],
                    'last_packet_time': time.time()
                }
            
            # Update flow statistics
            flow = self.flow_data[flow_key]
            flow['packet_count'] += 1
            flow['total_bytes'] += len(packet_data)
            flow['packet_sizes'].append(len(packet_data))
            
            current_time = time.time()
            if flow['packet_count'] > 1:
                inter_arrival = current_time - flow['last_packet_time']
                flow['inter_arrival_times'].append(inter_arrival)
            
            flow['last_packet_time'] = current_time
            
            # Extract TCP flags if protocol is TCP
            if protocol == 6 and len(packet_data) >= 34 + ip_length:
                tcp_header = packet_data[14 + ip_length:14 + ip_length + 20]
                if len(tcp_header) >= 14:
                    flags = struct.unpack('!B', tcp_header[13:14])[0]
                    if 'tcp_flags' not in flow:
                        flow['tcp_flags'] = {}
                    
                    # Update flag counts
                    for flag, mask in [
                        ('FIN', 0x01), ('SYN', 0x02), ('RST', 0x04),
                        ('PSH', 0x08), ('ACK', 0x10), ('URG', 0x20)
                    ]:
                        if flags & mask:
                            flow['tcp_flags'][flag] = flow['tcp_flags'].get(flag, 0) + 1
    
    def get_flow_features(self) -> List[Dict]:
        """
        Extract features from collected flow data for the current interval
        
        Returns:
            List of flow feature dictionaries
        """
        current_time = time.time()
        result = []
        
        with self.lock:
            for flow_key, flow in list(self.flow_data.items()):
                # Calculate flow duration
                flow_duration = current_time - flow['start_time']
                
                # Skip flows with very short duration or too few packets
                if flow_duration < 0.1 or flow['packet_count'] < 3:
                    continue
                
                # Calculate features
                features = {
                    'src_ip': flow['src_ip'],
                    'dst_ip': flow['dst_ip'],
                    'Protocol': flow['protocol'],
                    'Flow Duration': flow_duration * 1000,  # Convert to milliseconds
                    'Total Fwd Packets': flow['packet_count'],
                    'Total Backward Packets': 0,  # Simplified - would need bidirectional tracking
                    'Total Length of Fwd Packets': flow['total_bytes'],
                    'Fwd Packet Length Max': max(flow['packet_sizes']) if flow['packet_sizes'] else 0,
                    'Fwd Packet Length Min': min(flow['packet_sizes']) if flow['packet_sizes'] else 0,
                    'Fwd Packet Length Mean': sum(flow['packet_sizes']) / len(flow['packet_sizes']) if flow['packet_sizes'] else 0,
                    'Fwd Packet Length Std': self._std_dev(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0,
                    'Flow Bytes/s': flow['total_bytes'] / flow_duration if flow_duration > 0 else 0,
                    'Flow Packets/s': flow['packet_count'] / flow_duration if flow_duration > 0 else 0,
                    'Flow IAT Mean': sum(flow['inter_arrival_times']) / len(flow['inter_arrival_times']) if flow['inter_arrival_times'] else 0,
                    'Flow IAT Std': self._std_dev(flow['inter_arrival_times']) if len(flow['inter_arrival_times']) > 1 else 0,
                    'Flow IAT Max': max(flow['inter_arrival_times']) if flow['inter_arrival_times'] else 0,
                    'Flow IAT Min': min(flow['inter_arrival_times']) if flow['inter_arrival_times'] else 0,
                }
                
                # Add TCP flags if present
                if 'tcp_flags' in flow:
                    for flag in ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG']:
                        features[f'Flag {flag}'] = flow['tcp_flags'].get(flag, 0)
                else:
                    for flag in ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG']:
                        features[f'Flag {flag}'] = 0
                
                result.append(features)
                
                # Reset flows older than sample_interval
                if current_time - flow['start_time'] > self.sample_interval:
                    del self.flow_data[flow_key]
        
        return result
    
    @staticmethod
    def _std_dev(values):
        """Calculate standard deviation"""
        if len(values) <= 1:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
    