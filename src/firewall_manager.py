# src/firewall_manager.py
import subprocess
import logging
import os
import time
from typing import Set, List, Dict

class FirewallManager:
    def __init__(self, block_duration: int = 3600):
        """
        Initialize the firewall manager
        
        Args:
            block_duration: Duration in seconds to block IPs (default: 1 hour)
        """
        self.blocked_ips = {}  # IP -> unblock_time
        self.block_duration = block_duration
        
        # Check if running as root
        if os.geteuid() != 0:
            logging.warning("FirewallManager should be run as root for iptables access")
        
        # Create iptables chain if it doesn't exist
        self._setup_iptables()
        
        logging.info("Firewall manager initialized")
    
    def _setup_iptables(self):
        """Setup the iptables chain for DDoS protection"""
        try:
            # Create the chain if it doesn't exist
            subprocess.run(
                ["iptables", "-N", "DDOS_PROTECTION"],
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            # Chain already exists, flush it
            subprocess.run(["iptables", "-F", "DDOS_PROTECTION"])
        
        # Ensure the chain is part of the INPUT chain
        try:
            subprocess.run(
                ["iptables", "-C", "INPUT", "-j", "DDOS_PROTECTION"],
                check=True,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            # Rule doesn't exist, add it
            subprocess.run(
                ["iptables", "-I", "INPUT", "-j", "DDOS_PROTECTION"]
            )
    
    def block_ips(self, ips: Set[str]) -> None:
        current_time = time.time()
        
        for ip in ips:
            try:
                # Skip if IP is whitelisted
                if ip in config.PROTECTION_SETTINGS['WHITELIST']:
                    continue
                
                # 1. Block all traffic from IP
                subprocess.run([
                    "iptables", "-A", "DDOS_PROTECTION",
                    "-s", ip,
                    "-j", "DROP"
                ], check=True)
                
                # 2. Add rate limiting for HTTP/HTTPS
                subprocess.run([
                    "iptables", "-A", "DDOS_PROTECTION",
                    "-p", "tcp",
                    "-s", ip,
                    "-m", "multiport",
                    "--dports", "80,443,8080",
                    "-m", "hashlimit",
                    "--hashlimit-above", "10/sec",
                    "--hashlimit-burst", "20",
                    "--hashlimit-mode", "srcip",
                    "--hashlimit-name", f"ddos_{ip.replace('.', '_')}",
                    "-j", "DROP"
                ], check=True)
                
                # 3. Limit SYN packets
                subprocess.run([
                    "iptables", "-A", "DDOS_PROTECTION",
                    "-p", "tcp",
                    "-s", ip,
                    "--syn",
                    "-m", "limit",
                    "--limit", "5/s",
                    "-j", "DROP"
                ], check=True)
                
                # 4. Limit UDP traffic
                subprocess.run([
                    "iptables", "-A", "DDOS_PROTECTION",
                    "-p", "udp",
                    "-s", ip,
                    "-m", "limit",
                    "--limit", "10/s",
                    "-j", "DROP"
                ], check=True)
                
                # 5. Limit ICMP
                subprocess.run([
                    "iptables", "-A", "DDOS_PROTECTION",
                    "-p", "icmp",
                    "-s", ip,
                    "-m", "limit",
                    "--limit", "1/s",
                    "-j", "DROP"
                ], check=True)
                
                self.blocked_ips[ip] = current_time + config.PROTECTION_SETTINGS['BLOCK_DURATION']
                logging.warning(f"Blocked IP {ip} with comprehensive rules")
                
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to block IP {ip}: {str(e)}")
    
    def unblock_expired(self) -> None:
        """Unblock any IPs that have exceeded their block duration"""
        current_time = time.time()
        
        for ip in list(self.blocked_ips.keys()):
            if current_time >= self.blocked_ips[ip]:
                try:
                    subprocess.run(
                        ["iptables", "-D", "DDOS_PROTECTION", "-s", ip, "-j", "DROP"],
                        check=True
                    )
                    
                    del self.blocked_ips[ip]
                    logging.info(f"Unblocked IP {ip}")
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to unblock IP {ip}: {str(e)}")
    
    def get_blocked_ips(self) -> List[Dict]:
        """
        Get a list of currently blocked IPs
        
        Returns:
            List of dictionaries with IP and time remaining
        """
        current_time = time.time()
        return [
            {
                'ip': ip,
                'time_remaining': max(0, int(unblock_time - current_time))
            }
            for ip, unblock_time in self.blocked_ips.items()
        ]

    def add_advanced_rules(self, ip: str) -> None:
        """Add advanced protection rules for specific attack types"""
        try:
            # Slowloris Protection
            subprocess.run([
                "iptables", "-A", "DDOS_PROTECTION",
                "-p", "tcp",
                "-s", ip,
                "--dport", "80",
                "-m", "connlimit",
                "--connlimit-above", "20",
                "-j", "DROP"
            ], check=True)

            # DNS Amplification Protection
            subprocess.run([
                "iptables", "-A", "DDOS_PROTECTION",
                "-p", "udp",
                "-s", ip,
                "--dport", "53",
                "-m", "limit",
                "--limit", "5/s",
                "-j", "DROP"
            ], check=True)

            # NTP Amplification Protection
            subprocess.run([
                "iptables", "-A", "DDOS_PROTECTION",
                "-p", "udp",
                "-s", ip,
                "--dport", "123",
                "-m", "limit",
                "--limit", "5/s",
                "-j", "DROP"
            ], check=True)

            # SSDP/UPnP Protection
            subprocess.run([
                "iptables", "-A", "DDOS_PROTECTION",
                "-p", "udp",
                "-s", ip,
                "--dport", "1900",
                "-j", "DROP"
            ], check=True)

            # Connection Tracking Protection
            subprocess.run([
                "iptables", "-A", "DDOS_PROTECTION",
                "-p", "tcp",
                "-s", ip,
                "-m", "state",
                "--state", "NEW",
                "-m", "limit",
                "--limit", "50/s",
                "--limit-burst", "100",
                "-j", "DROP"
            ], check=True)

        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to add advanced rules for IP {ip}: {str(e)}")

    def add_rate_limiting(self, ip: str) -> None:
        """Add rate limiting rules"""
        try:
            # TCP Rate Limiting
            subprocess.run([
                "iptables", "-A", "DDOS_PROTECTION",
                "-p", "tcp",
                "-s", ip,
                "-m", "hashlimit",
                "--hashlimit-name", f"tcp_limit_{ip.replace('.', '_')}",
                "--hashlimit-above", "100/sec",
                "--hashlimit-burst", "150",
                "--hashlimit-mode", "srcip",
                "-j", "DROP"
            ], check=True)

            # UDP Rate Limiting
            subprocess.run([
                "iptables", "-A", "DDOS_PROTECTION",
                "-p", "udp",
                "-s", ip,
                "-m", "hashlimit",
                "--hashlimit-name", f"udp_limit_{ip.replace('.', '_')}",
                "--hashlimit-above", "50/sec",
                "--hashlimit-burst", "100",
                "--hashlimit-mode", "srcip",
                "-j", "DROP"
            ], check=True)

        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to add rate limiting for IP {ip}: {str(e)}")

    def cleanup(self):
        """Clean up iptables rules when shutting down"""
        try:
            # Unblock all IPs
            for ip in list(self.blocked_ips.keys()):
                subprocess.run(
                    ["iptables", "-D", "DDOS_PROTECTION", "-s", ip, "-j", "DROP"],
                    stderr=subprocess.DEVNULL
                )
            
            # Remove the chain from INPUT
            subprocess.run(
                ["iptables", "-D", "INPUT", "-j", "DDOS_PROTECTION"],
                stderr=subprocess.DEVNULL
            )
            
            # Flush and delete the chain
            subprocess.run(["iptables", "-F", "DDOS_PROTECTION"])
            subprocess.run(["iptables", "-X", "DDOS_PROTECTION"])
            
            logging.info("Firewall rules cleaned up")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error cleaning up firewall rules: {str(e)}")