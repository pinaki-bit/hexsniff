import time
import json
import asyncio
from typing import Dict, Any, List
from app.db_manager import db_engine

class CorrelationEngine:
    def __init__(self):
        self.engine = db_engine
        self.running = False
        
    def get_connection(self):
        return self.engine.get_connection()

    def process_alerts(self):
        """Finds uncorrelated alerts and links them to attack chains."""
        with self.get_connection() as conn:
            # Get latest 100 alerts
            rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100").fetchall()
            alerts = [dict(r) for r in rows]
            
            # Group by src_ip
            by_src = {}
            for a in alerts:
                if not a["src_ip"] or a["src_ip"] == "N/A": continue
                if a["src_ip"] not in by_src:
                    by_src[a["src_ip"]] = []
                by_src[a["src_ip"]].append(a)
                
            for src_ip, ip_alerts in by_src.items():
                # Sort chronological
                ip_alerts.sort(key=lambda x: x["timestamp"])
                
                # Check for existing open chain
                chain_row = conn.execute("SELECT * FROM attack_chains WHERE src_ip = ? AND status = 'Open'", (src_ip,)).fetchone()
                
                if chain_row:
                    chain = dict(chain_row)
                    tactics = json.loads(chain["tactics_progression"] or "[]")
                    a_ids = json.loads(chain["alert_ids"] or "[]")
                    
                    updated = False
                    for a in ip_alerts:
                        if a["alert_id"] not in a_ids:
                            a_ids.append(a["alert_id"])
                            if a["mitre_tactic"] and a["mitre_tactic"] not in tactics:
                                tactics.append(a["mitre_tactic"])
                            updated = True
                            
                    if updated:
                        conn.execute('''
                            UPDATE attack_chains 
                            SET last_update = ?, tactics_progression = ?, alert_ids = ?
                            WHERE chain_id = ?
                        ''', (time.time(), json.dumps(tactics), json.dumps(a_ids), chain["chain_id"]))
                else:
                    # Only create a chain if there are multiple tactics or high severity
                    if len(ip_alerts) > 1 or any(a["severity"] in ("High", "Critical") for a in ip_alerts):
                        chain_id = f"chain_{src_ip}_{int(time.time())}"
                        tactics = []
                        a_ids = []
                        for a in ip_alerts:
                            a_ids.append(a["alert_id"])
                            if a["mitre_tactic"] and a["mitre_tactic"] not in tactics:
                                tactics.append(a["mitre_tactic"])
                                
                        conn.execute('''
                            INSERT INTO attack_chains (chain_id, src_ip, start_time, last_update, tactics_progression, alert_ids, status)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (chain_id, src_ip, ip_alerts[0]["timestamp"], time.time(), json.dumps(tactics), json.dumps(a_ids), "Open"))
            
            conn.commit()

    async def run_loop(self):
        self.running = True
        print("[CorrelationEngine] Started background correlation worker.")
        while self.running:
            try:
                # Use run_in_executor to avoid blocking the event loop with SQLite I/O
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self.process_alerts)
            except Exception as e:
                print(f"[CorrelationEngine] Error: {e}")
            await asyncio.sleep(5)  # Run every 5 seconds

    def stop(self):
        self.running = False

    def insert_alert(self, alert: Dict[str, Any]):
        """Helper to dump an alert into the DB for correlation."""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT OR IGNORE INTO alerts (alert_id, timestamp, category, severity, message, src_ip, dst_ip, proto, mitre_technique, mitre_tactic, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.get("id"),
                alert.get("timestamp", time.time()),
                alert.get("category"),
                alert.get("severity"),
                alert.get("message"),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert.get("proto"),
                alert.get("mitre_technique"),
                alert.get("mitre_tactic"),
                alert.get("confidence", 50)
            ))
            conn.commit()
            
    def get_attack_chains(self):
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM attack_chains ORDER BY last_update DESC").fetchall()
            return [dict(r) for r in rows]

correlation_engine = CorrelationEngine()
