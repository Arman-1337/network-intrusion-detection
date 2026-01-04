"""
Packet Sniffer Module
Captures network packets for analysis
"""
import time
from datetime import datetime
from typing import Callable, Optional
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.packet import Packet
import threading

class PacketSniffer:
    """Captures and processes network packets."""
    
    def __init__(self, interface: str = None, callback: Optional[Callable] = None):
        """
        Initialize packet sniffer.
        
        Args:
            interface: Network interface to sniff on
            callback: Function to call for each packet
        """
        self.interface = interface
        self.callback = callback
        self.running = False
        self.packet_count = 0
        self.start_time = None
        
    def process_packet(self, packet: Packet):
        """
        Process captured packet.
        
        Args:
            packet: Scapy packet object
        """
        self.packet_count += 1
        
        # Extract packet information
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'number': self.packet_count,
            'length': len(packet),
        }
        
        # IP layer
        if IP in packet:
            packet_info.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'ttl': packet[IP].ttl,
            })
            
            # TCP layer
            if TCP in packet:
                packet_info.update({
                    'transport': 'TCP',
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'flags': str(packet[TCP].flags),
                })
            
            # UDP layer
            elif UDP in packet:
                packet_info.update({
                    'transport': 'UDP',
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport,
                })
            
            # ICMP layer
            elif ICMP in packet:
                packet_info.update({
                    'transport': 'ICMP',
                    'type': packet[ICMP].type,
                    'code': packet[ICMP].code,
                })
        
        # Call callback if provided
        if self.callback:
            self.callback(packet_info)
        
        return packet_info
    
    def start(self, count: int = 0, timeout: Optional[int] = None):
        """
        Start packet capture.
        
        Args:
            count: Number of packets to capture (0 = infinite)
            timeout: Timeout in seconds (None = no timeout)
        """
        self.running = True
        self.start_time = time.time()
        
        print(f"\n{'='*70}")
        print(f"  PACKET SNIFFER STARTED")
        print(f"{'='*70}")
        print(f"  Interface: {self.interface or 'Default'}")
        print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                count=count,
                timeout=timeout,
                store=False
            )
        except PermissionError:
            print("\n❌ ERROR: Administrator privileges required for packet capture!")
            print("   Run as administrator or use a different interface.")
            self.running = False
        except Exception as e:
            print(f"\n❌ ERROR: {str(e)}")
            self.running = False
    
    def stop(self):
        """Stop packet capture."""
        self.running = False
        
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"\n{'='*70}")
            print(f"  PACKET CAPTURE STOPPED")
            print(f"{'='*70}")
            print(f"  Total packets: {self.packet_count}")
            print(f"  Duration: {duration:.2f} seconds")
            print(f"  Rate: {self.packet_count/duration:.2f} packets/sec")
            print(f"{'='*70}\n")
    
    def get_stats(self) -> dict:
        """Get sniffer statistics."""
        if self.start_time:
            duration = time.time() - self.start_time
            rate = self.packet_count / duration if duration > 0 else 0
        else:
            duration = 0
            rate = 0
        
        return {
            'packet_count': self.packet_count,
            'duration': duration,
            'rate': rate,
            'running': self.running
        }