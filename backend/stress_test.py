import sys
import time
import asyncio
import os

from scapy.all import IP, TCP, Raw

sys.path.append(os.getcwd())
from app.analyzer import PacketAnalyzer

async def stress_test():
    print("\n--- PHASE 6 PACKET ENGINE STRESS TEST ---")
    analyzer = PacketAnalyzer()
    pkt = IP(src="192.168.1.5", dst="8.8.8.8") / TCP(sport=12345, dport=443, flags="A") / Raw(b"Encrypted Payload Data")
    
    count = 100000
    
    print(f"Injecting {count} packets to measure pure throughput...")
    start_time = time.time()
    for _ in range(count):
        analyzer.analyze_packet(pkt)
    duration = time.time() - start_time
    
    pps = count / duration
    print(f"Time taken: {duration:.2f} seconds")
    print(f"Packets Processed/sec: {pps:.0f} PPS")
    
if __name__ == "__main__":
    asyncio.run(stress_test())
