import asyncio
import websockets
import json
import urllib.request
import time
import threading

def generate_traffic():
    urls = [
        "https://www.youtube.com",
        "https://www.google.com",
        "https://www.github.com",
        "https://open.spotify.com"
    ]
    for _ in range(5):
        for url in urls:
            try:
                urllib.request.urlopen(url, timeout=2)
            except Exception:
                pass
            time.sleep(0.5)

async def test_throughput():
    uri = "ws://127.0.0.1:8000/ws/packets"
    print(f"Connecting to {uri}...")
    
    total_packets = 0
    first_packet = None
    
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected! Starting live capture on ALL interfaces...")
            await websocket.send(json.dumps({"action": "start_live", "interface": None}))
            
            # Start background traffic generator
            traffic_thread = threading.Thread(target=generate_traffic)
            traffic_thread.start()
            
            start_time = time.time()
            print("Listening for packets (15 seconds)...")
            
            while time.time() - start_time < 15:
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    data = json.loads(response)
                    
                    if data.get("type") in ("info", "error"):
                        print(f"System: {data}")
                        continue
                        
                    total_packets += 1
                    if first_packet is None:
                        first_packet = data
                except asyncio.TimeoutError:
                    continue
            
            print("\n--- PHASE 1.3 THROUGHPUT STATS ---")
            print(f"Duration: 15 seconds")
            print(f"Total Packets Processed & Streamed: {total_packets}")
            print(f"Average PPS: {total_packets / 15:.2f}")
            print("----------------------------------\n")
            
            if first_packet:
                print("--- PHASE 1.1 END-TO-END TRACE EVIDENCE ---")
                print(f"Packet ID: {first_packet.get('id')}")
                print(f"Protocol: {first_packet.get('proto')}")
                print(f"Source IP: {first_packet.get('src_ip')}:{first_packet.get('src_port')}")
                print(f"Destination IP: {first_packet.get('dst_ip')}:{first_packet.get('dst_port')}")
                print(f"Length: {first_packet.get('length')} bytes")
                print(f"Timestamp: {first_packet.get('timestamp')}")
                print("Raw Payload (first 50 chars):")
                print(first_packet.get('ascii_dump', '')[:50].replace('\n', ' '))
                print("-------------------------------------------\n")
            
            await websocket.send(json.dumps({"action": "stop"}))
    except Exception as e:
        print(f"WebSocket error: {e}")

if __name__ == "__main__":
    asyncio.run(test_throughput())
