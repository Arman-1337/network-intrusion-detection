"""
Alert Management System
Handles and distributes security alerts
"""
import os
from datetime import datetime
from typing import List, Dict
import json

class AlertManager:
    """Manages security alerts and notifications."""
    
    def __init__(self, log_file: str = "logs/alerts.log"):
        """
        Initialize alert manager.
        
        Args:
            log_file: Path to alert log file
        """
        self.log_file = log_file
        self.alerts = []
        
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    def create_alert(self, alert_type: str, severity: str, 
                    description: str, **kwargs):
        """
        Create a new security alert.
        
        Args:
            alert_type: Type of alert
            severity: Severity level (HIGH, MEDIUM, LOW)
            description: Alert description
            **kwargs: Additional alert data
        """
        alert = {
            'id': len(self.alerts) + 1,
            'type': alert_type,
            'severity': severity,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        
        self.alerts.append(alert)
        
        # Console alert
        self._console_alert(alert)
        
        # File alert
        self._file_alert(alert)
        
        return alert
    
    def _console_alert(self, alert: Dict):
        """Print alert to console."""
        severity_colors = {
            'HIGH': '🔴',
            'MEDIUM': '🟠',
            'LOW': '🟡'
        }
        
        icon = severity_colors.get(alert['severity'], '⚪')
        
        print(f"\n{icon} ALERT [{alert['severity']}] - {alert['type']}")
        print(f"   {alert['description']}")
        print(f"   Time: {alert['timestamp']}")
        
        if 'source_ip' in alert:
            print(f"   Source IP: {alert['source_ip']}")
        
        print()
    
    def _file_alert(self, alert: Dict):
        """Write alert to log file."""
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def get_alerts(self, severity: str = None, limit: int = 100) -> List[Dict]:
        """
        Get alerts, optionally filtered by severity.
        
        Args:
            severity: Filter by severity level
            limit: Maximum number of alerts to return
            
        Returns:
            List of alerts
        """
        if severity:
            filtered = [a for a in self.alerts if a['severity'] == severity]
        else:
            filtered = self.alerts
        
        return filtered[-limit:]
    
    def get_statistics(self) -> Dict:
        """Get alert statistics."""
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts = {}
        
        for alert in self.alerts:
            severity_counts[alert['severity']] += 1
            
            alert_type = alert['type']
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        
        return {
            'total_alerts': len(self.alerts),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'recent_alerts': self.alerts[-10:]
        }
    
    def clear_alerts(self):
        """Clear all alerts."""
        self.alerts.clear()