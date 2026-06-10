import sys
import time
import asyncio
import httpx
import websockets
import psutil
import json
import uuid
import os

from scapy.all import IP, TCP, Raw

sys.path.append(os.getcwd())
from app.analyzer import PacketAnalyzer
from app.case_manager import CaseManager

async def run_packet_throughput():
    print("\n--- STEP 4: PACKET THROUGHPUT BENCHMARK ---")
    analyzer = PacketAnalyzer()
    
    # Create a baseline packet
    pkt = IP(src="10.0.0.5", dst="192.168.1.100") / TCP(sport=12345, dport=80, flags="S") / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    
    for count in [10000, 50000, 100000]:
        print(f"\nInjecting {count} packets into Analyzer...")
        start = time.time()
        for _ in range(count):
            analyzer.analyze_packet(pkt)
        duration = time.time() - start
        pps = count / duration
        print(f"Processed: {count} packets")
        print(f"Time: {duration:.3f} seconds")
        print(f"PPS: {pps:.0f} packets/sec")
        
        proc = psutil.Process()
        mem_mb = proc.memory_info().rss / 1024 / 1024
        print(f"Memory Usage: {mem_mb:.1f} MB")

async def run_db_stress():
    print("\n--- STEP 8: DATABASE AUDIT ---")
    cm = CaseManager()
    
    for count in [100, 1000, 5000]:
        print(f"\nInjecting {count} cases into SQLite...")
        start = time.time()
        for i in range(count):
            cid = str(uuid.uuid4())
            cm.create_case(cid, f"Stress Test Case {i}", "Open", "Medium", "benchmark")
        duration = time.time() - start
        cps = count / duration
        print(f"Write Latency: {duration:.3f} seconds ({cps:.0f} inserts/sec)")
        
        start = time.time()
        cases = cm.list_cases()
        duration = time.time() - start
        print(f"Read Latency ({len(cases)} total cases): {duration:.3f} seconds")

async def run_security_check():
    print("\n--- STEP 11: SECURITY REVIEW ---")
    print("Testing Case API path traversal...")
    async with httpx.AsyncClient() as client:
        # Try to access a file via case API
        res = await client.get("http://127.0.0.1:8000/api/cases/../../../etc/passwd")
        print(f"GET /api/cases/../../../etc/passwd -> {res.status_code} (Should be 404)")

        # Test validation upload boundary
        print("Testing PCAP Upload validation...")
        res = await client.post("http://127.0.0.1:8000/api/upload-pcap", files={"file": ("malicious.exe", b"MZ", "application/x-msdownload")})
        print(f"Upload malicious.exe -> {res.status_code} (Should be 400)")

async def main():
    print("Initializing HexSniff Phase 5 Benchmarks...")
    await run_packet_throughput()
    await run_db_stress()
    await run_security_check()
    print("\nBenchmarks complete.")

if __name__ == "__main__":
    asyncio.run(main())
