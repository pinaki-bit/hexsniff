import time
import json
from typing import Dict, Any, List
from app.db_manager import db_engine

class AssetManager:
    def __init__(self):
        self.engine = db_engine
        
    def get_connection(self):
        return self.engine.get_connection()

    def upsert_asset(self, ip: str, mac: str = "N/A", open_port: int = None, os_guess: str = "Unknown"):
        if not ip or ip == "N/A" or ip == "0.0.0.0" or ip == "255.255.255.255":
            return
            
        # Only track private IPs as internal assets
        if not (ip.startswith("192.168.") or ip.startswith("10.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)):
            return

        now = time.time()
        
        with self.get_connection() as conn:
            # Check if exists
            row = conn.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()
            
            if not row:
                ports = [open_port] if open_port else []
                conn.execute('''
                    INSERT INTO assets (ip, mac, first_seen, last_seen, open_ports, os_guess, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (ip, mac, now, now, json.dumps(ports), os_guess, 0))
            else:
                asset = dict(row)
                ports = json.loads(asset["open_ports"] or "[]")
                
                updated = False
                if open_port and open_port not in ports:
                    ports.append(open_port)
                    updated = True
                    
                new_mac = mac if mac != "N/A" and asset["mac"] == "N/A" else asset["mac"]
                if new_mac != asset["mac"]:
                    updated = True
                    
                new_os = os_guess if os_guess != "Unknown" and asset["os_guess"] == "Unknown" else asset["os_guess"]
                if new_os != asset["os_guess"]:
                    updated = True
                    
                # Throttle last_seen updates to avoid db spam (e.g. max once per minute)
                if updated or (now - asset["last_seen"] > 60):
                    conn.execute('''
                        UPDATE assets SET mac = ?, last_seen = ?, open_ports = ?, os_guess = ?
                        WHERE ip = ?
                    ''', (new_mac, now, json.dumps(ports), new_os, ip))
            conn.commit()

    def list_assets(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM assets ORDER BY last_seen DESC").fetchall()
            return [dict(r) for r in rows]

asset_manager = AssetManager()
