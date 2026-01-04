"""
Main IDS Engine
Coordinates all IDS components
"""
import threading
import time
from typing import Optional

from .core.sniffer import PacketSniffer
from .detectors.anomaly_detector import AnomalyDetector
from .detectors.rule_detector import RuleDetector
from .alerts.alert_manager import AlertManager
from .core.config import config

class IDSEngine:
    """Main Intrusion Detection System engine."""
    
    def __init__(self):
        """Initialize IDS engine."""
        self.sniffer = None
        self.anomaly_detector = AnomalyDetector()
        self.rule_detector = RuleDetector()
        self.alert_manager = AlertManager(config.ALERT_LOG_FILE)
        
        self.running = False
        self.stats = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'alerts_generated': 0
        }
    
    def packet_callback(self, packet_info: dict):
        """
        Process each captured packet.
        
        Args:
            packet_info: Packet information dictionary
        """
        self.stats['packets_processed'] += 1
        
        # Check for anomalies
        if config.ENABLE_ANOMALY_DETECTION:
            anomalies = self.anomaly_detector.analyze_packet(packet_info)
            
            for anomaly in anomalies:
                self.stats['anomalies_detected'] += 1
                self.stats['alerts_generated'] += 1
                
                self.alert_manager.create_alert(
                    alert_type=anomaly['type'],
                    severity=anomaly['severity'],
                    description=anomaly['description'],
                    source_ip=anomaly.get('source_ip'),
                    timestamp=anomaly['timestamp']
                )
        
        # Check against rules
        if config.ENABLE_RULE_DETECTION:
            rule_alerts = self.rule_detector.check_packet(packet_info)
            
            for alert in rule_alerts:
                self.stats['alerts_generated'] += 1
                
                self.alert_manager.create_alert(
                    alert_type=alert['rule_name'],
                    severity=alert['severity'],
                    description=alert['description'],
                    source_ip=alert.get('source_ip'),
                    destination_port=alert.get('destination_port'),
                    rule_id=alert.get('rule_id')
                )
    
    def start(self, interface: str = None, count: int = 0, timeout: int = None):
        """
        Start the IDS engine.
        
        Args:
            interface: Network interface to monitor
            count: Number of packets to capture (0 = infinite)
            timeout: Capture timeout in seconds
        """
        self.running = True
        
        print("\n" + "=" * 70)
        print("  NETWORK INTRUSION DETECTION SYSTEM")
        print("=" * 70)
        print(f"  Interface: {interface or 'Auto-detect'}")
        print(f"  Anomaly Detection: {'Enabled' if config.ENABLE_ANOMALY_DETECTION else 'Disabled'}")
        print(f"  Rule Detection: {'Enabled' if config.ENABLE_RULE_DETECTION else 'Disabled'}")
        print(f"  Alert Logging: {config.ALERT_LOG_FILE}")
        print("=" * 70)
        
        # Create sniffer
        self.sniffer = PacketSniffer(
            interface=interface or config.INTERFACE,
            callback=self.packet_callback
        )
        
        # Start sniffing
        try:
            self.sniffer.start(count=count, timeout=timeout)
        except KeyboardInterrupt:
            print("\n\nStopping IDS...")
            self.stop()
    
    def stop(self):
        """Stop the IDS engine."""
        self.running = False
        
        if self.sniffer:
            self.sniffer.stop()
        
        # Print final statistics
        self.print_statistics()
    
    def print_statistics(self):
        """Print IDS statistics."""
        print("\n" + "=" * 70)
        print("  IDS STATISTICS")
        print("=" * 70)
        print(f"  Packets Processed: {self.stats['packets_processed']:,}")
        print(f"  Anomalies Detected: {self.stats['anomalies_detected']:,}")
        print(f"  Alerts Generated: {self.stats['alerts_generated']:,}")
        print("=" * 70)
        
        # Alert breakdown
        alert_stats = self.alert_manager.get_statistics()
        print(f"\n  Alert Breakdown:")
        print(f"    🔴 HIGH: {alert_stats['by_severity']['HIGH']}")
        print(f"    🟠 MEDIUM: {alert_stats['by_severity']['MEDIUM']}")
        print(f"    🟡 LOW: {alert_stats['by_severity']['LOW']}")
        print("\n" + "=" * 70 + "\n")
    
    def get_statistics(self) -> dict:
        """Get current IDS statistics."""
        return {
            'engine': self.stats,
            'anomaly_detector': self.anomaly_detector.get_statistics(),
            'rule_detector': self.rule_detector.get_statistics(),
            'alert_manager': self.alert_manager.get_statistics()
        }