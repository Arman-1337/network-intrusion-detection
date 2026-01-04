"""
IDS Configuration Settings
"""
from dataclasses import dataclass
from typing import List
import os

@dataclass
class IDSConfig:
    """IDS configuration settings."""
    
    # Network Settings
    INTERFACE: str = "Wi-Fi"  # Change to your network interface
    PROMISCUOUS_MODE: bool = False  # Set True for full packet capture (needs admin)
    
    # Detection Settings
    ENABLE_ANOMALY_DETECTION: bool = True
    ENABLE_RULE_DETECTION: bool = True
    
    # Anomaly Thresholds
    MAX_PACKETS_PER_SECOND: int = 1000
    MAX_CONNECTIONS_PER_IP: int = 50
    MAX_PORTS_SCANNED: int = 20
    SUSPICIOUS_PORT_THRESHOLD: int = 10
    
    # Alert Settings
    ENABLE_CONSOLE_ALERTS: bool = True
    ENABLE_FILE_ALERTS: bool = True
    ENABLE_EMAIL_ALERTS: bool = False
    
    ALERT_LOG_FILE: str = "logs/alerts.log"
    PACKET_LOG_FILE: str = "logs/packets.log"
    
    # Dashboard Settings
    DASHBOARD_HOST: str = "127.0.0.1"
    DASHBOARD_PORT: int = 5000
    DASHBOARD_UPDATE_INTERVAL: int = 5  # seconds
    
    # Data Retention
    MAX_PACKETS_IN_MEMORY: int = 10000
    MAX_ALERTS_IN_MEMORY: int = 1000
    
    # Suspicious Ports (commonly attacked)
    SUSPICIOUS_PORTS: List[int] = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        27017, # MongoDB
    ]
    
    # Known Attack Patterns
    ATTACK_SIGNATURES: List[str] = [
        "union select",
        "' or '1'='1",
        "../etc/passwd",
        "<script>",
        "cmd.exe",
        "/bin/bash",
    ]

config = IDSConfig()