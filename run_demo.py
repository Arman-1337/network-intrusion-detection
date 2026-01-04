"""
Run IDS in Demo Mode with Dashboard
"""
import threading
import time
from ids.ids_engine import IDSEngine
from ids.web.app import run_dashboard
from ids.core.config import config
import random
from datetime import datetime

def generate_demo_traffic(ids_engine):
    """Generate continuous fake traffic."""
    
    fake_ips = [
        '192.168.1.100', '192.168.1.101', '10.0.0.50',
        '172.16.0.10', '8.8.8.8', '1.1.1.1', '203.0.113.5'
    ]
    
    protocols = ['TCP', 'UDP', 'ICMP']
    ports = [22, 23, 80, 443, 3306, 3389, 8080, 21, 25, 53]
    
    print("\n🎮 DEMO MODE: Generating continuous fake traffic...")
    print("=" * 70)
    
    packet_num = 0
    
    while True:
        packet_num += 1
        
        # Create fake packet
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'number': packet_num,
            'length': random.randint(64, 1500),
            'src_ip': random.choice(fake_ips),
            'dst_ip': random.choice(fake_ips),
            'protocol': random.randint(1, 17),
            'ttl': random.randint(64, 128),
            'transport': random.choice(protocols),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(ports)
        }
        
        # Process through IDS
        ids_engine.packet_callback(packet_info)
        
        # Print progress occasionally
        if packet_num % 50 == 0:
            print(f"  Generated {packet_num} packets...")
        
        # Random delay between packets
        time.sleep(random.uniform(0.1, 0.5))

def main():
    """Run IDS in demo mode."""
    print("\n" + "=" * 70)
    print("  NETWORK IDS - DEMO MODE")
    print("=" * 70)
    print("\n  🎮 Running in DEMO mode with simulated traffic")
    print("  📊 Dashboard: http://127.0.0.1:5000")
    print("\n  Press Ctrl+C to stop\n")
    
    # Create IDS engine
    ids = IDSEngine()
    
    # Start dashboard in separate thread
    dashboard_thread = threading.Thread(
        target=run_dashboard,
        args=(ids,),
        daemon=True
    )
    dashboard_thread.start()
    
    # Give dashboard time to start
    time.sleep(2)
    
    # Start traffic generator in separate thread
    traffic_thread = threading.Thread(
        target=generate_demo_traffic,
        args=(ids,),
        daemon=True
    )
    traffic_thread.start()
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Shutting down demo...")
        ids.print_statistics()
        print("\n✅ Demo stopped!\n")

if __name__ == '__main__':
    main()