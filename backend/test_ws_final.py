import asyncio
import websockets
import json

async def test_ws():
    async with websockets.connect('ws://127.0.0.1:8000/ws/packets') as ws:
        print("Connected!")
        await ws.send(json.dumps({'action': 'start_replay', 'speed': 100.0}))
        msg = await asyncio.wait_for(ws.recv(), timeout=5)
        print("Received: ", msg[:100] + "...")

asyncio.run(test_ws())
