import asyncio
import websockets
import json

async def test():
    async with websockets.connect("ws://127.0.0.1:8000/ws/packets") as ws:
        print("Connected!")
        await ws.send(json.dumps({"action": "start_live", "interface": "loopback"}))
        print("Sent start_live")
        try:
            await asyncio.wait_for(ws.recv(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        # Now close it abruptly
        
asyncio.run(test())
