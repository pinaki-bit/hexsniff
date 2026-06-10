import asyncio
import websockets
import json

async def test_capture():
    uri = "ws://127.0.0.1:8000/ws/packets"
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected! Sending start_live request for default interface.")
            await websocket.send(json.dumps({"action": "start_live", "interface": "default"})) # Most systems will fall back to default if not found
            
            packet_count = 0
            while packet_count < 10:
                response = await websocket.recv()
                data = json.loads(response)
                
                if data.get("type") in ("info", "error"):
                    print(f"System Message: {data}")
                    continue
                    
                print(f"Packet Captured:")
                print(f"  Proto: {data.get('proto')}")
                print(f"  Src: {data.get('src_ip')}:{data.get('src_port')} -> Dst: {data.get('dst_ip')}:{data.get('dst_port')}")
                print(f"  Summary: {data.get('summary')}")
                print(f"  Length: {data.get('length')} bytes")
                print("-" * 40)
                
                packet_count += 1
                
            await websocket.send(json.dumps({"action": "stop"}))
            print("Capture stopped.")
    except Exception as e:
        print(f"WebSocket error: {e}")

if __name__ == "__main__":
    asyncio.run(test_capture())
