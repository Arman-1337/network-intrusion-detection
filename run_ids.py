"""
Run the Network IDS
"""
import sys
import threading
import time
from ids.ids_engine import IDSEngine
from ids.web.app import run_dashboard
from ids.core.config import config

def main():
    """Main function to run IDS."""
    print("\n" + "=" * 70)
    print("  NETWORK INTRUSION DETECTION SYSTEM v1.0")
    print("=" * 70)
    
    # Ask user for mode
    print("\n  Select Mode:")
    print("  1. Real-time Packet Capture (requires admin/Npcap)")
    print("  2. Demo Mode (simulated traffic)")
    
    choice = input("\n  Enter choice (1 or 2): ").strip()
    
    if choice == '2':
        print("\n  Starting in DEMO mode...")
        run_demo_mode()
    else:
        print("\n  Starting in REAL CAPTURE mode...")
        run_capture_mode()

def run_capture_mode():
    """Run IDS with real packet capture."""
    print("\n  Starting system components...")
    
    # Create IDS engine
    ids = IDSEngine()
    
    # Start dashboard in separate thread
    print(f"\n  📊 Dashboard: http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print("  🔍 Starting packet capture...")
    print("\n  ⚠️  Note: Packet capture requires:")
    print("     - Administrator/root privileges")
    print("     - Npcap installed (Windows)")
    print("\n  Press Ctrl+C to stop\n")
    
    dashboard_thread = threading.Thread(
        target=run_dashboard,
        args=(ids,),
        daemon=True
    )
    dashboard_thread.start()
    
    # Give dashboard time to start
    time.sleep(2)
    
    try:
        # Start IDS (this will block)
        ids.start(timeout=None)
    except PermissionError:
        print("\n" + "=" * 70)
        print("  ❌ PERMISSION ERROR")
        print("=" * 70)
        print("\n  Packet capture requires administrator privileges!")
        print("\n  Solutions:")
        print("  1. Run Command Prompt as Administrator")
        print("  2. Use Demo Mode instead (run_demo.py)")
        print("  3. Install Npcap: https://npcap.com")
        print("\n" + "=" * 70 + "\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Shutting down IDS...")
        ids.stop()
        print("\n✅ IDS stopped successfully!\n")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        print("\n  Try running in Demo Mode: python run_demo.py")
        sys.exit(1)

def run_demo_mode():
    """Run IDS with simulated traffic."""
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
        
        print("\n🎮 Generating simulated network traffic...")
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
    
    # Create IDS engine
    ids = IDSEngine()
    
    print(f"\n  📊 Dashboard: http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print("  🎮 Running simulated traffic")
    print("\n  Press Ctrl+C to stop\n")
    
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
        print("\n\n⚠️  Shutting down...")
        ids.print_statistics()
        print("\n✅ Demo stopped!\n")

if __name__ == '__main__':
    main()