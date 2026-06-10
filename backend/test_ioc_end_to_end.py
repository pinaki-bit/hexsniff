import asyncio
import websockets
import json
import urllib.request
import time
import threading
import subprocess

async def end_to_end_test():
    print("--- 1. SYNCING THREAT FEEDS ---")
    req = urllib.request.Request("http://127.0.0.1:8000/api/iocs/sync", method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        sync_result = json.loads(resp.read().decode())
    print(f"Sync complete. Ingested {sync_result.get('count')} unique IOCs.")

    print("\n--- 2. RETRIEVING TARGET IOC ---")
    req = urllib.request.urlopen("http://127.0.0.1:8000/api/iocs")
    iocs = json.loads(req.read().decode())
    target_ioc = None
    for ioc in iocs:
        if ioc.get("type") == "IP" and ioc.get("source") == "Feodo Tracker":
            target_ioc = ioc
            break
            
    if not target_ioc:
        print("Failed to find an IP IOC.")
        return
        
    target_ip = target_ioc.get("value") or target_ioc.get("indicator")
    print(f"Selected Target IOC: {target_ip} ({target_ioc.get('description')})")
    print(f"Mapped MITRE Technique: {target_ioc.get('mitre')}")

    print("\n--- 3. STARTING CAPTURE ENGINE ---")
    uri = "ws://127.0.0.1:8000/ws/packets"
    alert_packet = None
    
    try:
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps({"action": "start_live", "interface": None}))
            
            # Spawn ping to generate traffic to the malicious IP
            def ping_target():
                time.sleep(1) # wait for capture to settle
                print(f"[Thread] Pinging malicious IOC {target_ip} to trigger IDS...")
                subprocess.run(["ping", "-n", "1", "-w", "1000", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            threading.Thread(target=ping_target).start()
            
            start_time = time.time()
            while time.time() - start_time < 5:
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    data = json.loads(response)
                    
                    if data.get("type") in ("info", "error"):
                        continue
                        
                    # Check if packet matches target IP and has an alert
                    if (data.get("src_ip") == target_ip or data.get("dst_ip") == target_ip):
                        if data.get("alerts"):
                            alert_packet = data
                            break
                except asyncio.TimeoutError:
                    continue
                    
            await websocket.send(json.dumps({"action": "stop"}))
    except Exception as e:
        print(f"WebSocket error: {e}")
        return

    if not alert_packet:
        print("Failed to capture an alert for the injected traffic.")
        return
        
    print("\n--- 4. ALERT GENERATION VERIFIED ---")
    alert = alert_packet["alerts"][0]
    print(f"Captured Packet ID: {alert_packet['id']}")
    print(f"Alert ID: {alert['id']}")
    print(f"Severity: {alert['severity']}")
    print(f"Message: {alert['message']}")
    print(f"MITRE Technique: {alert['mitre_technique']}")
    print(f"MITRE Tactic: {alert['mitre_tactic']}")

    print("\n--- 5. AI OVERSEER PROCESSING ---")
    ai_payload = {
        "packets": [alert_packet],
        "alerts": [alert]
    }
    
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/ai/analyze",
        data=json.dumps(ai_payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        ai_result = json.loads(resp.read().decode())
        
    print(f"AI Engine Source: {ai_result.get('source')}")
    print("AI Analysis Output snippet:")
    print(ai_result.get('analysis')[:300] + "...\n")
    
    print("\n--- END-TO-END TRACE SUCCESSFUL ---")

if __name__ == "__main__":
    asyncio.run(end_to_end_test())
