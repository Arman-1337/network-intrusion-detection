"""
Test if packet capture is working
"""
from scapy.all import sniff, IP

def packet_callback(packet):
    if IP in packet:
        print(f"✅ Captured packet: {packet[IP].src} -> {packet[IP].dst}")

print("Testing packet capture for 10 seconds...")
print("Open a website in your browser while this runs!")
print("=" * 60)

try:
    sniff(prn=packet_callback, timeout=10, count=10)
except PermissionError:
    print("\n❌ Need admin rights!")
    print("Run Command Prompt as Administrator")
except Exception as e:
    print(f"\n❌ Error: {e}")

print("\nDone!")