"""
Generate demo traffic for testing the IDS
"""
import time
import random
from datetime import datetime

def generate_demo_packets(ids_engine, num_packets=100):
    """Generate fake packets to test the IDS."""
    
    print("\n🎮 DEMO MODE: Generating fake traffic...")
    print("=" * 70)
    
    fake_ips = [
        '192.168.1.100', '192.168.1.101', '10.0.0.50',
        '172.16.0.10', '8.8.8.8', '1.1.1.1'
    ]
    
    protocols = ['TCP', 'UDP', 'ICMP']
    ports = [22, 23, 80, 443, 3306, 3389, 8080, 21, 25, 53]
    
    for i in range(num_packets):
        # Create fake packet
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'number': i + 1,
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
        
        # Print progress
        if (i + 1) % 10 == 0:
            print(f"  Generated {i + 1}/{num_packets} packets...")
        
        # Small delay
        time.sleep(0.1)
    
    print(f"\n✅ Generated {num_packets} demo packets!")
    print("=" * 70)
    print("\n📊 Check dashboard: http://127.0.0.1:5000")
    print("   You should see stats and alerts!\n")

if __name__ == '__main__':
    from ids.ids_engine import IDSEngine
    
    # Create IDS engine
    ids = IDSEngine()
    
    # Generate demo traffic
    generate_demo_packets(ids, num_packets=200)
    
    # Keep running so you can view dashboard
    print("\nPress Ctrl+C to stop...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n✅ Demo stopped!")
        ids.print_statistics()