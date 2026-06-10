import os
import time
import uuid
from typing import Dict, List, Any, Optional
from app.db_manager import db_engine

class CaseManager:
    def __init__(self):
        self.engine = db_engine

    def _get_connection(self):
        return self.engine.get_connection()

    def create_case(self, case_id: str, title: str, status: str = "Open", severity: str = "Medium", tags: str = "") -> Dict[str, Any]:
        now = time.time()
        with self._get_connection() as conn:
            conn.execute('''
                INSERT INTO cases (case_id, title, status, severity, notes, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (case_id, title, status, severity, "", tags, now, now))
            conn.commit()
            
            self.add_timeline_event(case_id, "CASE_CREATED", f"Case '{title}' created with status {status}")
            
        return self.get_case(case_id)

    def update_case(self, case_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        now = time.time()
        
        # Fetch existing to compare for timeline events
        existing = self.get_case(case_id)
        if not existing:
            return None
            
        update_fields = []
        params = []
        
        timeline_events = []
        
        if "status" in updates and updates["status"] != existing["status"]:
            update_fields.append("status = ?")
            params.append(updates["status"])
            timeline_events.append(("STATUS_CHANGED", f"Status changed from {existing['status']} to {updates['status']}"))
            
        if "severity" in updates and updates["severity"] != existing["severity"]:
            update_fields.append("severity = ?")
            params.append(updates["severity"])
            timeline_events.append(("SEVERITY_CHANGED", f"Severity changed from {existing['severity']} to {updates['severity']}"))
            
        if "notes" in updates and updates["notes"] != existing["notes"]:
            update_fields.append("notes = ?")
            params.append(updates["notes"])
            timeline_events.append(("NOTES_UPDATED", "Analyst notes were updated"))
            
        if "tags" in updates and updates["tags"] != existing["tags"]:
            update_fields.append("tags = ?")
            params.append(updates["tags"])
            
        if not update_fields:
            return existing
            
        update_fields.append("updated_at = ?")
        params.append(now)
        params.append(case_id)
        
        query = f"UPDATE cases SET {', '.join(update_fields)} WHERE case_id = ?"
        
        with self._get_connection() as conn:
            conn.execute(query, tuple(params))
            conn.commit()
            
            for evt_type, desc in timeline_events:
                conn.execute('''
                    INSERT INTO case_timeline (event_id, case_id, timestamp, event_type, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (str(uuid.uuid4()), case_id, now, evt_type, desc))
            conn.commit()
            
        return self.get_case(case_id)

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return None
                
            case_data = dict(row)
            
            # Fetch evidence
            evidence_rows = conn.execute("SELECT * FROM case_evidence WHERE case_id = ?", (case_id,)).fetchall()
            case_data["evidence"] = [dict(r) for r in evidence_rows]
            
            # Fetch timeline
            timeline_rows = conn.execute("SELECT * FROM case_timeline WHERE case_id = ? ORDER BY timestamp DESC", (case_id,)).fetchall()
            case_data["timeline"] = [dict(r) for r in timeline_rows]
            
            return case_data

    def list_cases(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT case_id, title, status, severity, tags, created_at, updated_at FROM cases ORDER BY updated_at DESC").fetchall()
            return [dict(r) for r in rows]

    def delete_case(self, case_id: str) -> bool:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM case_timeline WHERE case_id = ?", (case_id,))
            conn.execute("DELETE FROM case_evidence WHERE case_id = ?", (case_id,))
            cursor = conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            conn.commit()
            return cursor.rowcount > 0

    def add_evidence(self, case_id: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        evidence_id = str(uuid.uuid4())
        now = time.time()
        
        with self._get_connection() as conn:
            conn.execute('''
                INSERT INTO case_evidence (evidence_id, case_id, packet_id, alert_id, ioc, mitre_technique, mitre_tactic)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                evidence_id, 
                case_id, 
                evidence.get("packet_id", ""), 
                evidence.get("alert_id", ""), 
                evidence.get("ioc", ""), 
                evidence.get("mitre_technique", ""), 
                evidence.get("mitre_tactic", "")
            ))
            
            desc_parts = []
            if evidence.get("packet_id"): desc_parts.append(f"Packet {evidence['packet_id']}")
            if evidence.get("alert_id"): desc_parts.append(f"Alert {evidence['alert_id']}")
            if evidence.get("ioc"): desc_parts.append(f"IOC {evidence['ioc']}")
            
            desc = f"Attached Evidence: {', '.join(desc_parts)}"
            
            conn.execute('''
                INSERT INTO case_timeline (event_id, case_id, timestamp, event_type, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), case_id, now, "EVIDENCE_ADDED", desc))
            
            conn.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
            conn.commit()
            
        return self.get_case(case_id)

    def add_timeline_event(self, case_id: str, event_type: str, description: str):
        now = time.time()
        with self._get_connection() as conn:
            conn.execute('''
                INSERT INTO case_timeline (event_id, case_id, timestamp, event_type, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), case_id, now, event_type, description))
            conn.execute("UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
            conn.commit()
case_manager = CaseManager()
