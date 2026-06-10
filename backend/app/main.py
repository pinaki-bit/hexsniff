import os
import sys
import shutil
import asyncio
import json
import threading
import time
from queue import Queue, Empty
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import uuid
from contextlib import asynccontextmanager

load_dotenv()

# Windows DLL Security Fix for Npcap
if sys.platform.startswith("win"):
    npcap_paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap"
    ]
    for path in npcap_paths:
        if os.path.exists(path):
            try:
                os.add_dll_directory(path)
            except Exception:
                pass

from scapy.config import conf
conf.use_npcap = True
from scapy.all import get_if_list, sniff, wrpcap, rdpcap, srp, Ether, ARP

try:
    from scapy.arch.windows import get_windows_if_list
except Exception:
    get_windows_if_list = None
from fastapi.responses import FileResponse
import urllib.request

from app.analyzer import PacketAnalyzer
from app.filters import DisplayFilterEvaluator
from app.coverage_engine import CoverageEngine
from app.case_manager import case_manager
from app.hunt_engine import hunt_engine
from app.correlation_engine import correlation_engine
from app.copilot_engine import copilot_engine
from app.asset_manager import asset_manager

app = FastAPI(title="HexSniff NDR Enterprise Backend")

coverage_engine = CoverageEngine()

# Enable CORS for frontend connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CopilotMessage(BaseModel):
    role: str
    content: str

class AIAnalysisRequest(BaseModel):
    query: Optional[str] = None
    history: Optional[List[CopilotMessage]] = []
    context_refs: Optional[Dict[str, str]] = None

class HuntQueryRequest(BaseModel):
    query: str
    
class HuntSearchRequest(BaseModel):
    entity: str
    params: Dict[str, Any]

class SnifferState:
    def __init__(self):
        self.mode: Optional[str] = None  # "live", "sim", "replay", None
        self.interface: Optional[str] = None
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.active_websockets: List[WebSocket] = []
        self.analyzer = PacketAnalyzer()
        self.packet_queue = Queue()
        self.display_filter: Optional[DisplayFilterEvaluator] = None
        self.send_task: Optional[asyncio.Task] = None

state = SnifferState()

def _best_ip(ips):
    import ipaddress
    candidates = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_link_local:
                candidates.append((1, ip))
            else:
                candidates.append((0, ip))
        except ValueError:
            candidates.append((1, ip))
    if not candidates:
        return 'No IP'
    candidates.sort()
    return candidates[0][1]


def _is_preferred_ip(ip_str):
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback or addr.is_link_local:
            return False
        return True
    except ValueError:
        return False


def _resolve_interfaces():
    """Cross-references Windows network adapters with Scapy/Npcap capture interfaces.
    Only shows interfaces that Npcap can actually capture on."""
    
    # Step 1: Get the list of interfaces Npcap can open (these are GUIDs or device strings)
    capture_keys = set(get_if_list())
    
    # Step 2: Build a mapping from GUID -> capture key, and collect friendly names
    guid_to_key = {}
    friendly_to_key = {}
    for key in capture_keys:
        try:
            iface_obj = conf.ifaces.get(key)
        except Exception:
            iface_obj = None
        if iface_obj:
            if hasattr(iface_obj, 'guid') and iface_obj.guid:
                guid_to_key[iface_obj.guid.upper()] = key
            if hasattr(iface_obj, 'name') and iface_obj.name:
                friendly_to_key[iface_obj.name] = key

    npcap_available = getattr(conf, 'use_npcap', False)
    results = []
    diagnostics = []

    # Step 3: Enumerate Windows interfaces
    windows_ifaces = []
    if get_windows_if_list is not None:
        try:
            windows_ifaces = get_windows_if_list()
        except Exception:
            windows_ifaces = []

    if windows_ifaces:
        for win in windows_ifaces:
            name = win.get('name', '').strip()
            description = win.get('description', name)
            guid = win.get('guid', '')
            ips = win.get('ips', [])
            # Filter to only IPv4 addresses
            ipv4_ips = [ip for ip in ips if '.' in ip]
            ip = ipv4_ips[0] if ipv4_ips else 'No IP'

            # An interface is capture-capable ONLY if its GUID is in get_if_list()
            # or its friendly name maps to a known capture key
            capture_key = None
            if guid and guid.upper() in guid_to_key:
                capture_key = guid_to_key[guid.upper()]
            elif name in friendly_to_key:
                capture_key = friendly_to_key[name]
            elif name in capture_keys:
                capture_key = name
            
            capture_capable = capture_key is not None

            diag_entry = {
                "name": name,
                "description": description,
                "ip": ip,
                "capture_capable": capture_capable,
                "guid": guid,
                "npcap_available": bool(npcap_available),
            }
            diagnostics.append(diag_entry)

            if not capture_capable:
                continue

            # Use the friendly name for sniff (Scapy resolves it internally)
            sniff_name = name

            if "Wi-Fi" in description or "Wireless" in description:
                description = f"📶 {description}"
            elif "Ethernet" in description:
                description = f"🖧 {description}"
            elif "Loopback" in description:
                description = f"🔄 {description}"

            results.append({
                "name": sniff_name,
                "description": f"{description} ({ip})",
                "ip": ip,
                "capture_capable": True,
                "guid": guid,
                "npcap_available": bool(npcap_available),
            })

    # Fallback to conf.ifaces if windows enumeration fails
    if not results:
        for key, iface in conf.ifaces.items():
            name = iface.name if hasattr(iface, 'name') else str(key)
            description = iface.description if hasattr(iface, 'description') else name
            ip = getattr(iface, 'ip', 'No IP')
            if not ip or ip == '0.0.0.0':
                ip = 'No IP'

            capture_capable = str(key) in capture_keys or name in capture_keys
            if not capture_capable:
                diagnostics.append({
                    "name": name, "description": description, "ip": ip,
                    "capture_capable": False, "guid": getattr(iface, 'guid', ''),
                    "npcap_available": bool(npcap_available),
                })
                continue

            if "Wi-Fi" in description or "Wireless" in description:
                description = f"📶 {description}"
            elif "Ethernet" in description:
                description = f"🖧 {description}"
            elif "Loopback" in description:
                description = f"🔄 {description}"

            results.append({
                "name": name, "description": f"{description} ({ip})", "ip": ip,
                "capture_capable": True, "guid": getattr(iface, 'guid', ''),
                "npcap_available": bool(npcap_available),
            })

    if not results:
        for name in get_if_list():
            results.append({
                "name": name, "description": name, "ip": "Unknown",
                "capture_capable": True, "guid": "", "npcap_available": bool(npcap_available),
            })

    # Sort: interfaces with active IPv4 addresses first, then by name
    results.sort(key=lambda x: (
        x["ip"] == "No IP" or x["ip"] == "Unknown",
        x["name"]
    ))
    return results, diagnostics


@app.get("/api/interfaces")
def get_interfaces():
    """Lists network interfaces available for capture, hiding unsupported adapters."""
    try:
        results, _ = _resolve_interfaces()
        return results
    except Exception as e:
        return [{"name": "default", "description": f"Default Interface (Error: {str(e)})", "ip": "Unknown", "capture_capable": False, "guid": "", "npcap_available": False}]


@app.get("/api/interfaces/diagnostics")
def get_interface_diagnostics():
    """Returns full interface audit including unsupported adapters."""
    try:
        results, diagnostics = _resolve_interfaces()
        return {
            "capture_interfaces": results,
            "all_adapters": diagnostics,
            "auto_select": results[0]["name"] if results else None,
            "npcap_available": getattr(conf, 'use_npcap', False),
        }
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    """Uploads a .pcap file, parses it, and caches a copy for replaying."""
    if not file.filename or not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported.")

    temp_dir = os.path.join(os.getcwd(), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, "upload.pcap")
    replay_path = os.path.join(temp_dir, "replay.pcap")

    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Copy to replay path for playback support
        shutil.copy(temp_path, replay_path)

        analyzer = PacketAnalyzer()
        parsed_packets = []
        
        def prn(pkt):
            try:
                parsed = analyzer.analyze_packet(pkt)
                parsed_packets.append(parsed)
            except Exception:
                pass

        sniff(offline=temp_path, prn=prn, count=300)
        
        return {
            "success": True,
            "filename": file.filename,
            "count": len(parsed_packets),
            "packets": parsed_packets
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse PCAP file: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.post("/api/validation/run")
async def validation_run(file: UploadFile = File(...)):
    """Runs a dedicated forensic validation session against a PCAP, extracting full evidence chains."""
    import uuid
    if not file.filename or not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported.")

    temp_dir = os.path.join(os.getcwd(), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    session_id = f"val_{uuid.uuid4().hex[:8]}"
    temp_path = os.path.join(temp_dir, f"{session_id}.pcap")

    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        analyzer = PacketAnalyzer()
        tracked_alerts = {}
        processed_count = 0
        
        start_time = time.time()
        
        def prn(pkt):
            nonlocal processed_count
            try:
                parsed = analyzer.analyze_packet(pkt)
                processed_count += 1
                pkt_id = parsed.get("id")
                
                for alert in parsed.get("alerts", []):
                    # Aggregate alert by signature and endpoints
                    cat = alert.get("category")
                    src = alert.get("src_ip")
                    dst = alert.get("dst_ip")
                    key = f"{cat}-{src}-{dst}"
                    
                    if key in tracked_alerts:
                        ext = tracked_alerts[key]
                        if pkt_id and pkt_id not in ext["packet_ids"]:
                            ext["packet_ids"].append(pkt_id)
                            # Keep up to 10 full evidence packets per detection to prevent massive JSON payloads
                            if len(ext["evidence_details"]) < 10:
                                ext["evidence_details"].append({
                                    "id": pkt_id,
                                    "summary": parsed.get("summary"),
                                    "hex_dump": parsed.get("hex_dump"),
                                    "ascii_dump": parsed.get("ascii_dump")
                                })
                        ext["evidence_packets"] = len(ext["packet_ids"])
                        
                        # Re-calculate confidence
                        base = 50
                        if ext["severity"] == "Critical": base = 80
                        if ext["severity"] == "High": base = 70
                        ext["confidence"] = min(100, base + (ext["evidence_packets"] * 2))
                    else:
                        base = 50
                        if alert.get("severity") == "Critical": base = 80
                        if alert.get("severity") == "High": base = 70
                        
                        tracked_alerts[key] = {
                            **alert,
                            "packet_ids": [pkt_id] if pkt_id else [],
                            "evidence_packets": 1,
                            "evidence_details": [{
                                "id": pkt_id,
                                "summary": parsed.get("summary"),
                                "hex_dump": parsed.get("hex_dump"),
                                "ascii_dump": parsed.get("ascii_dump")
                            }] if pkt_id else [],
                            "confidence": base
                        }
            except Exception as e:
                print(f"[Validation Engine] Packet parsing error: {e}")

        # Validation requires full PCAP evaluation (bounded to 5000 packets to prevent OOM)
        sniff(offline=temp_path, prn=prn, count=5000)
        
        duration = time.time() - start_time
        
        # Format response and compute threat score
        detections = []
        for ext in tracked_alerts.values():
            score = 0
            # Base from severity
            sev = ext.get("severity", "Low")
            if sev == "Critical": score += 40
            elif sev == "High": score += 30
            elif sev == "Medium": score += 15
            else: score += 5
            
            # IOC bump
            if ext.get("ioc_hit"):
                if sev == "Critical": score += 30
                elif sev == "High": score += 20
                else: score += 10
                
            # Evidence bump
            score += min(20, ext.get("evidence_packets", 1) * 2)
            
            # Confidence bump
            score += min(10, ext.get("confidence", 50) / 10)
            
            # MITRE risk bump
            tactic = ext.get("mitre_tactic", "")
            if tactic in ["Command and Control", "Exfiltration", "Impact"]: score += 15
            elif tactic in ["Initial Access", "Credential Access", "Lateral Movement"]: score += 10
            
            score = int(min(100, max(0, score)))
            ext["threat_score"] = score
            
            if score >= 80: ext["risk_level"] = "CRITICAL"
            elif score >= 60: ext["risk_level"] = "HIGH"
            elif score >= 30: ext["risk_level"] = "MEDIUM"
            else: ext["risk_level"] = "LOW"
            
            detections.append(ext)

        # Sort by highest threat score
        detections.sort(key=lambda x: x.get("threat_score", 0), reverse=True)
        
        techniques = sorted(list({d.get("mitre_technique") for d in detections if d.get("mitre_technique")}))
        ioc_hits = [d for d in detections if d.get("ioc_hit")]

        result = {
            "session_id": session_id,
            "timestamp": int(time.time()),
            "pcap_name": file.filename,
            "packets_processed": processed_count,
            "duration_sec": round(duration, 3),
            "detections": detections,
            "ioc_hits": ioc_hits,
            "techniques": techniques,
            "status": "complete"
        }
        
        # Phase 5: Hook into backend coverage model
        coverage_engine.register_validation_session(result)
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.get("/api/download-pcap")
def download_pcap():
    """Serves the raw packet capture accumulated during the active session."""
    temp_pcap = os.path.join(os.getcwd(), "temp", "capture.pcap")
    if not os.path.exists(temp_pcap):
        try:
            os.makedirs(os.path.dirname(temp_pcap), exist_ok=True)
            # Write an empty PCAP header
            wrpcap(temp_pcap, [])
        except Exception:
            raise HTTPException(status_code=500, detail="Capture file could not be generated.")
    return FileResponse(temp_pcap, media_type="application/octet-stream", filename="hexsniff-capture.pcap")

@app.get("/api/iocs")
def get_iocs():
    """Returns the list of operational threat indicators cached on the backend."""
    return state.analyzer.ids_engine.iocs

@app.get("/api/coverage/stats")
def get_coverage_stats():
    """Returns the Phase 5 MITRE ATT&CK coverage model and detection statistics."""
    return coverage_engine.get_stats()

@app.post("/api/topology/scan")
async def scan_topology(subnet: Optional[str] = "192.168.1.0/24"):
    """Performs a Scapy ARP scan on the local subnet to discover active hosts.
    Returns only real ARP respondents — never fabricates hosts.
    """
    try:
        def run_scan():
            try:
                ans, unans = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet),
                    timeout=2.0,
                    verbose=False
                )
                hosts = []
                for snd, rcv in ans:
                    hosts.append({
                        "ip": rcv.psrc,
                        "mac": rcv.hwsrc,
                        "vendor": None,   # OUI lookup not available without manuf package
                        "alive": True
                    })
                return hosts
            except Exception as e:
                print("Topology scan error:", e)
                return []

        loop = asyncio.get_running_loop()
        hosts = await loop.run_in_executor(None, run_scan)
        
        # Phase 8: Also upsert these active scan results into the asset inventory
        for h in hosts:
            asset_manager.upsert_asset(h["ip"], h["mac"])
            
        # Return only what the ARP scan actually found — empty list is valid
        return {"success": True, "subnet": subnet, "hosts": hosts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Active scan failed: {str(e)}")

@app.get("/api/assets")
async def get_assets():
    """Returns the passively and actively discovered asset inventory."""
    return asset_manager.list_assets()

@app.get("/api/correlation/chains")
async def get_attack_chains():
    """Returns the active correlated attack chains."""
    return correlation_engine.get_attack_chains()

@app.post("/api/iocs/sync")
async def sync_ioc_feeds():
    """Fetches live threat indicators from Feodo Tracker and URLhaus.
    No API keys required. Replaces ioc_list.json with fresh data and
    hot-reloads the in-memory IOC list in the running IDS engine.
    """
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, state.analyzer.ids_engine.sync_feeds)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IOC sync failed: {str(e)}")

@app.get("/api/iocs/export")
async def export_iocs():
    """Exports all IOCs as a downloadable JSON file."""
    iocs = state.analyzer.ids_engine.iocs
    temp_dir = os.path.join(os.getcwd(), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, "iocs_export.json")
    with open(temp_path, 'w', encoding='utf-8') as f:
        json.dump(iocs, f, indent=2)
    return FileResponse(temp_path, media_type="application/json", filename="hexsniff_iocs.json")

@app.post("/api/iocs/import")
async def import_iocs(file: UploadFile = File(...)):
    """Imports a list of IOCs from an uploaded JSON file."""
    if not file.filename or not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Only .json files are supported for import.")
    
    try:
        content = await file.read()
        new_iocs = json.loads(content.decode('utf-8'))
        if not isinstance(new_iocs, list):
            raise ValueError("Root element must be a JSON array.")
            
        added_count = state.analyzer.ids_engine.import_iocs(new_iocs)
        return {"success": True, "imported_count": len(new_iocs), "new_additions": added_count}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to import IOCs: {str(e)}")

@app.post("/api/ai/analyze")
async def analyze_traffic(req: AIAnalysisRequest):
    try:
        history = [{"role": m.role, "content": m.content} for m in req.history] if req.history else []
        query = req.query or "Generate an initial Executive Summary of the global network state."
        ans = copilot_engine.process_chat(history, query, req.context_refs)
        return {"success": True, "analysis": ans, "source": "Open-Source LLM"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ------------------------------------------------------------------------------
# 10. Threat Hunting APIs (Phase 10)
# ------------------------------------------------------------------------------

@app.post("/api/hunt/search")
async def hunt_search(req: HuntSearchRequest):
    try:
        results = hunt_engine.search(req.entity, req.params)
        return {"success": True, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/hunt/graph")
async def hunt_graph():
    try:
        graph = hunt_engine.build_threat_graph()
        return {"success": True, "graph": graph}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/hunt/pivot")
async def hunt_pivot(source_type: str, source_id: str, target_type: str):
    try:
        results = hunt_engine.pivot(source_type, source_id, target_type)
        return {"success": True, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/hunt/query")
async def hunt_nl_query(req: HuntQueryRequest):
    """
    Translates Natural Language to Hunt Engine tool calls via Copilot.
    """
    try:
        # We reuse Copilot Engine to translate NL to hunt calls.
        # This is a specialized system prompt for just returning the JSON structure of a query.
        prompt = f"Convert the following threat hunting query into a JSON search object. Only return the JSON. Query: {req.query}"
        ans = copilot_engine.process_chat([], prompt)
        
        # In a full implementation we'd reliably parse the JSON. 
        # For this prototype we will assume copilot returns valid structured JSON search if prompted.
        try:
            import json
            import re
            match = re.search(r'\{.*\}', ans, re.DOTALL)
            if match:
                search_dict = json.loads(match.group(0))
                entity = search_dict.pop("entity", "alerts")
                results = hunt_engine.search(entity, search_dict)
                return {"success": True, "interpreted_query": search_dict, "entity": entity, "results": results}
        except Exception:
            pass
            
        return {"success": False, "error": "Could not interpret query."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def live_sniff_worker(interface: str, stop_event: threading.Event, queue: Queue, loop: asyncio.AbstractEventLoop, analyzer: PacketAnalyzer):
    """Background worker thread that runs Scapy's sniff loop and caches raw packets."""
    captured_count = 0
    queued_count = 0

    def packet_callback(pkt):
        nonlocal captured_count, queued_count
        try:
            captured_count += 1
            # Append raw frames to local PCAP cache
            temp_pcap = os.path.join(os.getcwd(), "temp", "capture.pcap")
            os.makedirs(os.path.dirname(temp_pcap), exist_ok=True)
            wrpcap(temp_pcap, pkt, append=True)

            parsed = analyzer.analyze_packet(pkt)
            queue.put(parsed)
            queued_count += 1
            loop.call_soon_threadsafe(lambda: None)
        except Exception as e:
            print(f"[HexSniff CAPTURE] packet_callback error: {e}")

    try:
        while not stop_event.is_set():
            sniff(
                iface=interface,
                prn=packet_callback,
                timeout=1.0,
                store=False
            )
    except Exception as e:
        error_msg = {
            "type": "error",
            "message": f"Sniffer error on interface '{interface}': {str(e)}."
        }
        queue.put(error_msg)
        loop.call_soon_threadsafe(lambda: None)

def replay_pcap_worker(pcap_path: str, stop_event: threading.Event, queue: Queue, loop: asyncio.AbstractEventLoop, analyzer: PacketAnalyzer, speed: float = 1.0):
    """Replays an uploaded PCAP file, sending packet streams over WebSocket with timing simulation."""
    try:
        packets = rdpcap(pcap_path)
        if not packets:
            queue.put({"type": "error", "message": "The PCAP file is empty."})
            loop.call_soon_threadsafe(lambda: None)
            return

        start_time = float(packets[0].time)
        start_wall = time.time()

        for pkt in packets:
            if stop_event.is_set():
                break

            # Replay delay timing simulation
            pkt_time = float(pkt.time)
            elapsed_pkt = pkt_time - start_time
            elapsed_wall = time.time() - start_wall

            sleep_time = (elapsed_pkt - elapsed_wall) / speed
            if sleep_time > 0:
                time.sleep(min(sleep_time, 1.0)) # cap single sleep at 1s to remain responsive

            parsed = analyzer.analyze_packet(pkt)
            # Shift timestamp to current wall clock time to animate properly in frontend
            parsed["timestamp"] = time.time()
            queue.put(parsed)
            loop.call_soon_threadsafe(lambda: None)

        queue.put({"type": "info", "message": "PCAP Replay playback completed."})
        loop.call_soon_threadsafe(lambda: None)
    except Exception as e:
        queue.put({"type": "error", "message": f"PCAP Replay failed: {str(e)}"})
        loop.call_soon_threadsafe(lambda: None)

async def check_queue_and_send(queue: Queue, stop_event: threading.Event):
    """Monitors the thread-safe queue, applies display filters, and broadcasts packets to all clients."""
    sent_count = 0
    filtered_count = 0
    while not stop_event.is_set():
        try:
            packet = queue.get_nowait()
            
            # Forward error/info system packets directly
            if isinstance(packet, dict) and packet.get("type") in ("error", "info"):
                dead_sockets = []
                for ws in state.active_websockets:
                    try:
                        await ws.send_json(packet)
                    except Exception:
                        dead_sockets.append(ws)
                for ws in dead_sockets:
                    if ws in state.active_websockets:
                        state.active_websockets.remove(ws)
                queue.task_done()
                continue
            
            # Phase 5: Register live alerts to Coverage Engine
            for alert in packet.get("alerts", []):
                coverage_engine.register_live_alert(alert)
                # Phase 8: Send alert to correlation engine DB
                correlation_engine.insert_alert(alert)

            # Phase 8: Asset Passive Discovery
            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            src_mac = packet.get("src_mac", "N/A")
            dst_mac = packet.get("dst_mac", "N/A")
            
            # Passively learn assets
            if src_ip:
                # If packet is TCP SYN/ACK (has both S and A), the source port is an open listening port on src_ip
                tcp_flags = packet.get("tcp_flags", "")
                open_port = packet.get("src_port") if ("S" in tcp_flags and "A" in tcp_flags) else None
                asset_manager.upsert_asset(src_ip, src_mac, open_port=open_port)
            if dst_ip:
                asset_manager.upsert_asset(dst_ip, dst_mac)

            # Apply active display filter on packet
            if state.display_filter:
                if not state.display_filter.evaluate(packet):
                    filtered_count += 1
                    queue.task_done()
                    continue

            dead_sockets = []
            for ws in state.active_websockets:
                try:
                    await ws.send_json(packet)
                except Exception:
                    dead_sockets.append(ws)
                    
            for ws in dead_sockets:
                if ws in state.active_websockets:
                    state.active_websockets.remove(ws)
                
            sent_count += 1
            queue.task_done()

        except Empty:
            await asyncio.sleep(0.02)
        except Exception as e:
            print(f"[HexSniff WS-SEND] Send error: {e}")
            break

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize geoip offline databases
    from app.db_manager import ensure_databases
    ensure_databases()
    # Ensure offline DBs downloaded before processing
    await geoip_resolver.ensure_offline_db()
    
    # Start the Correlation Engine background worker
    asyncio.create_task(correlation_engine.run_loop())
    
    yield
    stop_active_session()
    correlation_engine.stop()

def stop_active_session():
    """Safely terminates any active simulation, live capture, or replay."""
    state.stop_event.set()
    state.mode = None
    state.interface = None
    
    if state.thread and state.thread.is_alive():
        state.thread.join(timeout=1.5)
    state.thread = None
    state.loop = None
    state.display_filter = None
    
    while not state.packet_queue.empty():
        try:
            state.packet_queue.get_nowait()
        except Empty:
            break




# ------------------------------------------------------------------------------
# CASE MANAGEMENT API ROUTES
# ------------------------------------------------------------------------------


class CaseCreateReq(BaseModel):
    title: str
    status: str = "Open"
    severity: str = "Medium"
    tags: str = ""

class CaseUpdateReq(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[str] = None

@app.get("/api/cases")
async def list_cases():
    return case_manager.list_cases()

@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    case_obj = case_manager.get_case(case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")
    return case_obj

@app.post("/api/cases")
async def create_case(req: CaseCreateReq):
    case_id = str(uuid.uuid4())
    return case_manager.create_case(case_id, req.title, req.status, req.severity, req.tags)

@app.put("/api/cases/{case_id}")
async def update_case(case_id: str, req: CaseUpdateReq):
    updates = {k: v for k, v in req.dict().items() if v is not None}
    if not updates:
        return case_manager.get_case(case_id)
    res = case_manager.update_case(case_id, updates)
    if not res:
        raise HTTPException(status_code=404, detail="Case not found")
    return res

@app.delete("/api/cases/{case_id}")
async def delete_case(case_id: str):
    success = case_manager.delete_case(case_id)
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"success": True}

# ------------------------------------------------------------------------------
# DETECTION ENGINEERING API ROUTES
# ------------------------------------------------------------------------------

class RulesUpdateReq(BaseModel):
    content: str

@app.get("/api/rules")
async def get_rules():
    """Returns the raw content of the custom IDS rules."""
    content = state.analyzer.ids_engine.get_rules_content()
    return {"content": content}

@app.post("/api/rules")
async def update_rules(req: RulesUpdateReq):
    """Updates the IDS rules and hot-reloads the engine."""
    success = state.analyzer.ids_engine.save_rules_content(req.content)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save rules.")
    return {"success": True, "message": "Rules updated successfully."}

@app.post("/api/cases/{case_id}/evidence")
async def add_case_evidence(case_id: str, req: dict):
    res = case_manager.add_evidence(case_id, req)
    if not res:
        raise HTTPException(status_code=404, detail="Case not found")
    return res

@app.post("/api/cases/{case_id}/timeline")
async def add_case_timeline(case_id: str, req: dict):
    case_manager.add_timeline_event(
        case_id, 
        req.get("event_type", "MANUAL_ENTRY"), 
        req.get("description", "")
    )
    return case_manager.get_case(case_id)

@app.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.active_websockets.append(websocket)
    print(f"WebSocket client connected. Active clients: {len(state.active_websockets)}")
    
    # Send current state to the connecting client so they can restore UI
    if state.mode == "live":
        await websocket.send_json({"type": "status", "mode": "live", "interface": state.interface})
        if state.send_task is None or state.send_task.done():
            state.send_task = asyncio.create_task(check_queue_and_send(state.packet_queue, state.stop_event))
    elif state.mode == "replay":
        await websocket.send_json({"type": "status", "mode": "replay"})
        if state.send_task is None or state.send_task.done():
            state.send_task = asyncio.create_task(check_queue_and_send(state.packet_queue, state.stop_event))
    
    # Only reset capture trace if NO session is active
    temp_pcap = os.path.join(os.getcwd(), "temp", "capture.pcap")
    if state.mode is None and os.path.exists(temp_pcap):
        try:
            os.remove(temp_pcap)
        except Exception:
            pass

    try:
        while True:
            data_str = await websocket.receive_text()
            data = json.loads(data_str)
            action = data.get("action")
            
            if action == "start_live":
                interface = data.get("interface")
                
                # Validate interface is capture-capable
                capture_capable_names = {i["name"] for i in _resolve_interfaces()[0]}
                if interface not in capture_capable_names:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Interface '{interface}' is not available for live capture. It may not be supported by Npcap."
                    })
                    continue
                
                # Deduplication: Attach to existing capture if matching
                if state.mode == "live" and state.interface == interface and state.thread and state.thread.is_alive():
                    await websocket.send_json({"type": "info", "message": f"Attached to existing live capture on {interface}"})
                    continue
                
                stop_active_session()
                
                state.mode = "live"
                state.interface = interface
                state.stop_event.clear()
                state.loop = asyncio.get_running_loop()
                
                state.thread = threading.Thread(
                    target=live_sniff_worker,
                    args=(interface, state.stop_event, state.packet_queue, state.loop, state.analyzer),
                    daemon=True
                )
                state.thread.start()
                if state.send_task is None or state.send_task.done():
                    state.send_task = asyncio.create_task(check_queue_and_send(state.packet_queue, state.stop_event))
                await websocket.send_json({"type": "info", "message": f"Started live capture on {interface}"})
                
            elif action == "start_replay":
                stop_active_session()
                
                speed = float(data.get("speed", 1.0))
                
                state.mode = "replay"
                state.stop_event.clear()
                state.loop = asyncio.get_running_loop()
                
                replay_path = os.path.join(os.getcwd(), "temp", "replay.pcap")
                if not os.path.exists(replay_path):
                    await websocket.send_json({"type": "error", "message": "No uploaded PCAP file found to replay. Please upload a file first."})
                    state.mode = None
                    continue
                
                state.thread = threading.Thread(
                    target=replay_pcap_worker,
                    args=(replay_path, state.stop_event, state.packet_queue, state.loop, state.analyzer, speed),
                    daemon=True
                )
                state.thread.start()
                if state.send_task is None or state.send_task.done():
                    state.send_task = asyncio.create_task(check_queue_and_send(state.packet_queue, state.stop_event))
                await websocket.send_json({"type": "info", "message": f"Started PCAP file playback replay at {speed}x speed"})

            elif action == "set_filter":
                filter_str = data.get("filter", "")
                if filter_str.strip():
                    try:
                        state.display_filter = DisplayFilterEvaluator(filter_str)
                        await websocket.send_json({"type": "info", "message": f"Applied display filter: {filter_str}"})
                    except Exception as e:
                        await websocket.send_json({"type": "error", "message": f"Failed compiling filter: {str(e)}"})
                else:
                    state.display_filter = None
                    await websocket.send_json({"type": "info", "message": "Cleared display filter"})

            elif action == "stop":
                stop_active_session()
                await websocket.send_json({"type": "info", "message": "Stopped capture/replay session"})
                
    except WebSocketDisconnect:
        print(f"WebSocket client disconnected.")
    except Exception as e:
        print("WebSocket error:", e)
    finally:
        if websocket in state.active_websockets:
            state.active_websockets.remove(websocket)
        print(f"Client removed. Active clients: {len(state.active_websockets)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
