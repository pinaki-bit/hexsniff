import time
with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Fix broadcast_packets start
old1 = '''async def check_queue_and_send(queue: Queue, stop_event: threading.Event):
    """Monitors the thread-safe queue, applies display filters, and broadcasts packets to all clients."""
    sent_count = 0
    filtered_count = 0
    while not stop_event.is_set():
        try:
            packet = queue.get_nowait()'''

new1 = '''async def check_queue_and_send(queue: Queue, stop_event: threading.Event):
    """Monitors the thread-safe queue, applies display filters, and broadcasts packets to all clients."""
    sent_count = 0
    filtered_count = 0
    last_ping = time.time()
    while not stop_event.is_set():
        try:
            packet = queue.get_nowait()
            last_ping = time.time()'''
            
code = code.replace(old1, new1)

# 2. Fix broadcast_packets Empty exception
old2 = '''        except Empty:
            await asyncio.sleep(0.02)
        except Exception as e:
            print(f"[HexSniff WS-SEND] Send error: {e}")'''

new2 = '''        except Empty:
            if time.time() - last_ping > 15:
                for ws in state.active_websockets:
                    try: await ws.send_json({"type": "info", "message": "keep-alive"})
                    except: pass
                last_ping = time.time()
            await asyncio.sleep(0.02)
        except Exception as e:
            print(f"[HexSniff WS-SEND] Send error: {e}")'''

code = code.replace(old2, new2)

# 3. Fix live_sniff_worker exception
old3 = '''        sniff(iface=interface, prn=prn, stop_filter=lambda x: stop_event.is_set(), store=False)
    except Exception as e:
        print(f"Live sniff worker crashed: {e}")'''

new3 = '''        sniff(iface=interface, prn=prn, stop_filter=lambda x: stop_event.is_set(), store=False)
    except Exception as e:
        print(f"Live sniff worker crashed: {e}")
        packet_queue.put({"type": "error", "message": f"Capture failed: {e}. Try running HexSniff as Administrator."})'''
        
code = code.replace(old3, new3)

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.write(code)

print('Success')
