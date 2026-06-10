import time
from collections import Counter
from scapy.all import sniff, conf
from app.analyzer import PacketAnalyzer

analyzer = PacketAnalyzer()
proto_counts = Counter()

# Find an active interface that is not loopback
active_iface = None
for name, iface in conf.ifaces.items():
    ip = getattr(iface, 'ip', None)
    if ip and ip != '0.0.0.0' and ip != '127.0.0.1':
        active_iface = iface.name if hasattr(iface, 'name') else str(name)
        break

if not active_iface:
    active_iface = conf.iface

print(f"Sniffing 20 packets on interface: {active_iface}...")

def process_packet(pkt):
    try:
        parsed = analyzer.analyze_packet(pkt)
        proto_counts[parsed['proto']] += 1
        print(f"[{parsed['proto']}] {parsed['summary']}")
    except Exception as e:
        pass

try:
    sniff(iface=active_iface, prn=process_packet, count=20, timeout=10)
    print("\nSummary of captured protocols:")
    for proto, count in proto_counts.items():
        print(f"- {proto}: {count}")
except Exception as e:
    print(f"Failed to capture packets on {active_iface}: {e}")
