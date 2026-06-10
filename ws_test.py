import asyncio
import websockets
import json

async def test():
    async with websockets.connect("ws://127.0.0.1:8000/ws/packets") as ws:
        print("Connected!")
        await ws.send(json.dumps({"action": "start_live", "interface": "Microsoft Wi-Fi Direct Virtual Adapter"}))
        print("Sent start_live")
        
        while True:
            try:
                data = await ws.recv()
                print("Received data")
                # print(data)
            except Exception as e:
                print("Exception:", e)
                break

asyncio.run(test())
