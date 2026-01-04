"""
Rule-Based Detection Engine
Detects attacks based on predefined rules
"""
from typing import List, Dict
import re

class RuleDetector:
    """Detects attacks using signature-based rules."""
    
    def __init__(self):
        """Initialize rule detector."""
        self.rules = self._load_default_rules()
        self.alerts = []
    
    def _load_default_rules(self) -> List[Dict]:
        """Load default detection rules."""
        return [
            {
                'id': 'RULE-001',
                'name': 'SSH Brute Force',
                'description': 'Multiple SSH connection attempts',
                'port': 22,
                'protocol': 'TCP',
                'threshold': 10,
                'severity': 'HIGH'
            },
            {
                'id': 'RULE-002',
                'name': 'RDP Brute Force',
                'description': 'Multiple RDP connection attempts',
                'port': 3389,
                'protocol': 'TCP',
                'threshold': 5,
                'severity': 'HIGH'
            },
            {
                'id': 'RULE-003',
                'name': 'Database Access Attempt',
                'description': 'Suspicious database port access',
                'port': 3306,
                'protocol': 'TCP',
                'threshold': 3,
                'severity': 'MEDIUM'
            },
            {
                'id': 'RULE-004',
                'name': 'Telnet Access',
                'description': 'Insecure Telnet protocol detected',
                'port': 23,
                'protocol': 'TCP',
                'threshold': 1,
                'severity': 'MEDIUM'
            },
            {
                'id': 'RULE-005',
                'name': 'FTP Access',
                'description': 'Unencrypted FTP detected',
                'port': 21,
                'protocol': 'TCP',
                'threshold': 1,
                'severity': 'LOW'
            }
        ]
    
    def check_packet(self, packet_info: dict) -> List[Dict]:
        """
        Check packet against rules.
        
        Args:
            packet_info: Packet information dictionary
            
        Returns:
            List of triggered alerts
        """
        alerts = []
        
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('transport')
        src_ip = packet_info.get('src_ip')
        
        if not (dst_port and protocol and src_ip):
            return alerts
        
        # Check each rule
        for rule in self.rules:
            if (rule['port'] == dst_port and 
                rule['protocol'] == protocol):
                
                alert = {
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': rule['severity'],
                    'source_ip': src_ip,
                    'destination_port': dst_port,
                    'description': rule['description'],
                    'timestamp': packet_info.get('timestamp')
                }
                
                alerts.append(alert)
                self.alerts.append(alert)
        
        return alerts
    
    def add_rule(self, rule: Dict):
        """Add a custom detection rule."""
        self.rules.append(rule)
    
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent alerts."""
        return self.alerts[-limit:]
    
    def get_statistics(self) -> Dict:
        """Get rule detection statistics."""
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for alert in self.alerts:
            severity = alert.get('severity', 'LOW')
            severity_counts[severity] += 1
        
        return {
            'total_alerts': len(self.alerts),
            'by_severity': severity_counts,
            'recent_alerts': self.alerts[-10:]
        }