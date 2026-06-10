import json
import os
import threading
from typing import Dict, List, Any

COVERAGE_FILE = os.path.join(os.getcwd(), "app", "rules", "coverage_db.json")

class CoverageEngine:
    def __init__(self):
        self.lock = threading.Lock()
        
        self.techniques: Dict[str, Dict[str, Any]] = {}
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.history: List[Dict[str, Any]] = []
        
        self.total_validation_runs = 0
        self.total_live_alerts = 0
        
        self.load_state()

    def load_state(self):
        try:
            if os.path.exists(COVERAGE_FILE):
                with open(COVERAGE_FILE, "r") as f:
                    data = json.load(f)
                    self.techniques = data.get("techniques", {})
                    self.rules = data.get("rules", {})
                    self.history = data.get("history", [])
                    self.total_validation_runs = data.get("total_validation_runs", 0)
                    self.total_live_alerts = data.get("total_live_alerts", 0)
        except Exception as e:
            print(f"[CoverageEngine] Error loading state: {e}")

    def save_state(self):
        try:
            os.makedirs(os.path.dirname(COVERAGE_FILE), exist_ok=True)
            with open(COVERAGE_FILE, "w") as f:
                json.dump({
                    "techniques": self.techniques,
                    "rules": self.rules,
                    "history": self.history,
                    "total_validation_runs": self.total_validation_runs,
                    "total_live_alerts": self.total_live_alerts
                }, f, indent=2)
        except Exception as e:
            print(f"[CoverageEngine] Error saving state: {e}")

    def register_live_alert(self, alert: dict):
        with self.lock:
            self.total_live_alerts += 1
            rule_name = alert.get("category", "Unknown")
            tech_id = alert.get("mitre_technique")
            tactic = alert.get("mitre_tactic")
            conf = alert.get("confidence", 50)
            
            # Update Rule
            if rule_name not in self.rules:
                self.rules[rule_name] = {
                    "rule_name": rule_name,
                    "trigger_count": 0,
                    "validation_hits": 0,
                    "evidence_packets": 0,
                    "confidence_sum": 0,
                    "confidence_avg": 0,
                    "low_conf_count": 0
                }
            r = self.rules[rule_name]
            r["trigger_count"] += 1
            r["confidence_sum"] += conf
            r["confidence_avg"] = round(r["confidence_sum"] / (r["trigger_count"] + r["validation_hits"]), 1)
            
            # Update Technique
            if tech_id and tactic:
                if tech_id not in self.techniques:
                    self.techniques[tech_id] = {
                        "technique_id": tech_id,
                        "tactic": tactic,
                        "detections": 0,
                        "evidence_packets": 0,
                        "validation_sessions": 0,
                        "confidence_sum": 0,
                        "confidence_avg": 0
                    }
                t = self.techniques[tech_id]
                t["detections"] += 1
                t["confidence_sum"] += conf
                t["confidence_avg"] = round(t["confidence_sum"] / t["detections"], 1)
            
            self.save_state()

    def register_validation_session(self, session_data: dict):
        with self.lock:
            self.total_validation_runs += 1
            detections = session_data.get("detections", [])
            
            unique_techs_in_session = set()
            
            for d in detections:
                rule_name = d.get("category", "Unknown")
                tech_id = d.get("mitre_technique")
                tactic = d.get("mitre_tactic")
                conf = d.get("confidence", 50)
                evid = d.get("evidence_packets", 1)
                
                is_low_confidence = conf < 60 or evid < 2
                
                # Update Rule
                if rule_name not in self.rules:
                    self.rules[rule_name] = {
                        "rule_name": rule_name,
                        "trigger_count": 0,
                        "validation_hits": 0,
                        "evidence_packets": 0,
                        "confidence_sum": 0,
                        "confidence_avg": 0,
                        "low_conf_count": 0
                    }
                r = self.rules[rule_name]
                r["validation_hits"] += 1
                r["evidence_packets"] += evid
                r["confidence_sum"] += conf
                r["confidence_avg"] = round(r["confidence_sum"] / (r["trigger_count"] + r["validation_hits"]), 1)
                if is_low_confidence:
                    r["low_conf_count"] += 1

                # Update Technique
                if tech_id and tactic:
                    unique_techs_in_session.add(tech_id)
                    if tech_id not in self.techniques:
                        self.techniques[tech_id] = {
                            "technique_id": tech_id,
                            "tactic": tactic,
                            "detections": 0,
                            "evidence_packets": 0,
                            "validation_sessions": 0,
                            "confidence_sum": 0,
                            "confidence_avg": 0
                        }
                    t = self.techniques[tech_id]
                    t["detections"] += 1
                    t["evidence_packets"] += evid
                    t["confidence_sum"] += conf
                    t["confidence_avg"] = round(t["confidence_sum"] / t["detections"], 1)

            for tech_id in unique_techs_in_session:
                self.techniques[tech_id]["validation_sessions"] += 1

            # Save history
            self.history.insert(0, {
                "session_id": session_data.get("session_id"),
                "date": session_data.get("timestamp"),
                "detections": len(detections),
                "techniques": len(unique_techs_in_session),
                "coverage_impact": len(unique_techs_in_session)
            })
            if len(self.history) > 100:
                self.history = self.history[:100]

            self.save_state()

    def get_stats(self) -> dict:
        with self.lock:
            # Generate gap analysis (12 Tactics)
            core_tactics = [
                "Initial Access", "Execution", "Persistence", "Privilege Escalation", 
                "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", 
                "Collection", "Command and Control", "Exfiltration", "Impact"
            ]
            
            coverage_by_tactic = {tac: {"techniques": 0, "evidence": 0, "detections": 0} for tac in core_tactics}
            
            for t in self.techniques.values():
                tac = t["tactic"]
                if tac in coverage_by_tactic:
                    coverage_by_tactic[tac]["techniques"] += 1
                    coverage_by_tactic[tac]["evidence"] += t["evidence_packets"]
                    coverage_by_tactic[tac]["detections"] += t["detections"]

            gaps = [tac for tac, data in coverage_by_tactic.items() if data["detections"] == 0]
            
            # False Positive Metrics
            total_val_hits = sum(r["validation_hits"] for r in self.rules.values())
            total_low_conf = sum(r["low_conf_count"] for r in self.rules.values())
            fpr = round((total_low_conf / total_val_hits * 100) if total_val_hits > 0 else 0, 1)

            return {
                "techniques": list(self.techniques.values()),
                "rules": list(self.rules.values()),
                "history": self.history,
                "coverage_by_tactic": coverage_by_tactic,
                "gaps": gaps,
                "total_validation_runs": self.total_validation_runs,
                "fpr": fpr,
                "total_low_confidence": total_low_conf
            }
