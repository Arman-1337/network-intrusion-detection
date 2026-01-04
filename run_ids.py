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
    print("\n  Starting system components...")
    
    # Create IDS engine
    ids = IDSEngine()
    
    # Start dashboard in separate thread
    print(f"\n  📊 Dashboard: http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print("  🔍 Starting packet capture...")
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
    except KeyboardInterrupt:
        print("\n\n⚠️  Shutting down IDS...")
        ids.stop()
        print("\n✅ IDS stopped successfully!\n")

if __name__ == '__main__':
    main()