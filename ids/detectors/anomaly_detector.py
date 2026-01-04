"""
Anomaly Detection Engine
Detects unusual network behavior
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List
import time

class AnomalyDetector:
    """Detects network anomalies using statistical analysis."""
    
    def __init__(self):
        """Initialize anomaly detector."""
        # Track connections per IP
        self.connections_per_ip = defaultdict(int)
        self.ip_first_seen = {}
        
        # Track port scans
        self.ports_per_ip = defaultdict(set)
        
        # Track packet rates
        self.packet_times = deque(maxlen=1000)
        
        # Track protocols
        self.protocol_counts = defaultdict(int)
        
        # Track anomalies
        self.anomalies = []
        
    def analyze_packet(self, packet_info: dict) -> List[dict]:
        """
        Analyze packet for anomalies.
        
        Args:
            packet_info: Dictionary with packet information
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        # Extract info
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('transport', 'Unknown')
        
        if not src_ip:
            return anomalies
        
        # Track packet timing
        self.packet_times.append(time.time())
        
        # Track connections
        self.connections_per_ip[src_ip] += 1
        
        # Track first time seeing this IP
        if src_ip not in self.ip_first_seen:
            self.ip_first_seen[src_ip] = time.time()
        
        # Track protocol
        self.protocol_counts[protocol] += 1
        
        # 1. Check for excessive connections from single IP
        if self.connections_per_ip[src_ip] > 50:
            anomalies.append({
                'type': 'Excessive Connections',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'description': f'IP {src_ip} has {self.connections_per_ip[src_ip]} connections',
                'timestamp': datetime.now().isoformat()
            })
        
        # 2. Check for port scanning
        if dst_port:
            self.ports_per_ip[src_ip].add(dst_port)
            
            if len(self.ports_per_ip[src_ip]) > 20:
                anomalies.append({
                    'type': 'Port Scan Detected',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'IP {src_ip} scanned {len(self.ports_per_ip[src_ip])} ports',
                    'ports': list(self.ports_per_ip[src_ip])[:10],
                    'timestamp': datetime.now().isoformat()
                })
        
        # 3. Check for high packet rate (DDoS indicator)
        if len(self.packet_times) >= 100:
            time_diff = self.packet_times[-1] - self.packet_times[0]
            if time_diff > 0:
                rate = len(self.packet_times) / time_diff
                
                if rate > 1000:  # More than 1000 packets/sec
                    anomalies.append({
                        'type': 'High Traffic Rate',
                        'severity': 'MEDIUM',
                        'description': f'Unusual traffic rate: {rate:.0f} packets/sec',
                        'rate': rate,
                        'timestamp': datetime.now().isoformat()
                    })
        
        # 4. Check for suspicious protocol distribution
        total_packets = sum(self.protocol_counts.values())
        if total_packets > 100:
            for proto, count in self.protocol_counts.items():
                percentage = (count / total_packets) * 100
                
                # Alert if any protocol is >90% of traffic
                if percentage > 90:
                    anomalies.append({
                        'type': 'Protocol Anomaly',
                        'severity': 'LOW',
                        'protocol': proto,
                        'description': f'{proto} traffic is {percentage:.1f}% of total',
                        'timestamp': datetime.now().isoformat()
                    })
        
        # Store detected anomalies
        for anomaly in anomalies:
            self.anomalies.append(anomaly)
        
        return anomalies
    
    def get_statistics(self) -> dict:
        """Get detection statistics."""
        return {
            'total_ips': len(self.connections_per_ip),
            'total_anomalies': len(self.anomalies),
            'connections_by_ip': dict(sorted(
                self.connections_per_ip.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'protocol_distribution': dict(self.protocol_counts),
            'recent_anomalies': self.anomalies[-10:]
        }
    
    def reset(self):
        """Reset detector state."""
        self.connections_per_ip.clear()
        self.ip_first_seen.clear()
        self.ports_per_ip.clear()
        self.packet_times.clear()
        self.protocol_counts.clear()
        self.anomalies.clear()