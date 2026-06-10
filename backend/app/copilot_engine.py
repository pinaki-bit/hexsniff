import os
import json
import urllib.request
from typing import List, Dict, Any
from dotenv import load_dotenv
load_dotenv()
from app.db_manager import db_engine
from app.ids_engine import IDSEngine
from app.hunt_engine import hunt_engine

class CopilotEngine:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY", "")
        self.base_url = os.environ.get("OPENAI_API_BASE", "https://api.groq.com/openai/v1")
        self.model = os.environ.get("OPENAI_MODEL", "llama-3.1-8b-instant")
        print(f"DEBUG API KEY: {self.api_key} | BASE: {self.base_url} | MODEL: {self.model}")
        self.db = db_engine

    def _get_connection(self):
        return self.db.get_connection()

    def execute_query(self, tool_name: str, args: dict) -> str:
        """Executes a local DB query based on the tool call and returns JSON string."""
        try:
            with self._get_connection() as conn:
                if tool_name == "query_assets":
                    ip_filter = args.get("ip_filter")
                    min_risk = int(args.get("min_risk", 0))
                    if ip_filter:
                        rows = conn.execute("SELECT * FROM assets WHERE ip LIKE ? AND risk_score >= ? LIMIT 50", (f"%{ip_filter}%", min_risk)).fetchall()
                    else:
                        rows = conn.execute("SELECT * FROM assets WHERE risk_score >= ? ORDER BY last_seen DESC LIMIT 50", (min_risk,)).fetchall()
                    return json.dumps([dict(r) for r in rows])

                elif tool_name == "query_alerts":
                    mitre_tactic = args.get("mitre_tactic")
                    src_ip = args.get("src_ip")
                    severity = args.get("severity")
                    
                    query = "SELECT * FROM alerts WHERE 1=1"
                    params = []
                    if mitre_tactic:
                        query += " AND mitre_tactic = ?"
                        params.append(mitre_tactic)
                    if src_ip:
                        query += " AND src_ip = ?"
                        params.append(src_ip)
                    if severity:
                        query += " AND severity = ?"
                        params.append(severity)
                    query += " ORDER BY timestamp DESC LIMIT 50"
                    
                    rows = conn.execute(query, params).fetchall()
                    return json.dumps([dict(r) for r in rows])

                elif tool_name == "query_attack_chains":
                    status = args.get("status")
                    src_ip = args.get("src_ip")
                    
                    query = "SELECT * FROM attack_chains WHERE 1=1"
                    params = []
                    if status:
                        query += " AND status = ?"
                        params.append(status)
                    if src_ip:
                        query += " AND src_ip = ?"
                        params.append(src_ip)
                    query += " ORDER BY last_update DESC LIMIT 20"
                    
                    rows = conn.execute(query, params).fetchall()
                    return json.dumps([dict(r) for r in rows])

                elif tool_name == "query_cases":
                    status = args.get("status", "Open")
                    query = "SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC LIMIT 20"
                    rows = conn.execute(query, (status,)).fetchall()
                    return json.dumps([dict(r) for r in rows])
                    
                elif tool_name == "threat_hunt":
                    entity = args.get("entity")
                    params = args.get("params", {})
                    results = hunt_engine.search(entity, params)
                    return json.dumps(results[:50]) # limit JSON size
                    
                elif tool_name == "hunt_pivot":
                    src_type = args.get("source_type")
                    src_id = args.get("source_id")
                    tgt_type = args.get("target_type")
                    results = hunt_engine.pivot(src_type, src_id, tgt_type)
                    return json.dumps(results[:50])
                    
                else:
                    return json.dumps({"error": f"Unknown tool {tool_name}"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def get_tools_definition(self):
        # OpenAI tool schema
        return [
            {
                "type": "function",
                "function": {
                    "name": "query_assets",
                    "description": "Searches the Enterprise Asset Inventory for known hosts.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ip_filter": {"type": "string", "description": "Optional IP or subnet"},
                            "min_risk": {"type": "string", "description": "Minimum risk score 0-100 as a number"}
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "query_alerts",
                    "description": "Searches raw IDS detections/alerts.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "mitre_tactic": {"type": "string", "description": "e.g., Initial Access, Command and Control"},
                            "src_ip": {"type": "string", "description": "Source IP address"},
                            "severity": {"type": "string", "description": "Critical, High, Medium, Low"}
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "query_attack_chains",
                    "description": "Searches correlated Attack Chains (multiple alerts grouped by attacker).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "status": {"type": "string", "description": "Open, Investigating, Closed"},
                            "src_ip": {"type": "string", "description": "Attacker Source IP"}
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "query_cases",
                    "description": "Searches active Analyst Cases.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "status": {"type": "string", "description": "Open, Investigating, Closed"}
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "threat_hunt",
                    "description": "Executes an advanced structured threat hunt using the Hunt Engine.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "entity": {"type": "string", "description": "The entity to search: assets, alerts, attack_chains, cases, mitre"},
                            "params": {"type": "object", "description": "Key-value pairs for filtering (e.g., {'severity': 'Critical', 'tactic': 'Execution'})"}
                        },
                        "required": ["entity", "params"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "hunt_pivot",
                    "description": "Pivots between related entities in the threat graph (e.g., from an asset to its alerts, or from an alert to an attack chain).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "source_type": {"type": "string", "description": "asset, alert, case, attack_chain"},
                            "source_id": {"type": "string", "description": "The ID of the source entity (e.g., IP address, Alert ID)"},
                            "target_type": {"type": "string", "description": "assets, alerts, attack_chains, cases"}
                        },
                        "required": ["source_type", "source_id", "target_type"]
                    }
                }
            }
        ]

    def _gather_context(self) -> str:
        """Pre-fetch key database data and return as a compact context string."""
        context_parts = []
        try:
            with self._get_connection() as conn:
                # Assets (top 10 by risk)
                assets = conn.execute("SELECT ip, hostname, os, risk_score, open_ports, last_seen FROM assets ORDER BY risk_score DESC LIMIT 10").fetchall()
                if assets:
                    context_parts.append(f"## ASSETS ({len(assets)} top-risk hosts)\n{json.dumps([dict(r) for r in assets])}")

                # Alerts (latest 10)
                alerts = conn.execute("SELECT id, severity, category, src_ip, dst_ip, mitre_tactic, description, timestamp FROM alerts ORDER BY timestamp DESC LIMIT 10").fetchall()
                if alerts:
                    context_parts.append(f"## ALERTS ({len(alerts)} recent)\n{json.dumps([dict(r) for r in alerts])}")

                # Attack Chains (latest 5)
                chains = conn.execute("SELECT * FROM attack_chains ORDER BY last_update DESC LIMIT 5").fetchall()
                if chains:
                    context_parts.append(f"## ATTACK CHAINS ({len(chains)})\n{json.dumps([dict(r) for r in chains])}")

                # Cases (latest 5)
                cases = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC LIMIT 5").fetchall()
                if cases:
                    context_parts.append(f"## CASES ({len(cases)})\n{json.dumps([dict(r) for r in cases])}")

                # Summary stats
                alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                critical_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'Critical'").fetchone()[0]
                high_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'High'").fetchone()[0]
                asset_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
                chain_count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
                
                summary = (
                    f"## NETWORK SUMMARY\n"
                    f"- Total Assets: {asset_count}\n"
                    f"- Total Alerts: {alert_count} (Critical: {critical_count}, High: {high_count})\n"
                    f"- Active Attack Chains: {chain_count}\n"
                )
                context_parts.insert(0, summary)
                
        except Exception as e:
            context_parts.append(f"[Database query error: {e}]")
        
        return "\n\n".join(context_parts)

    def process_chat(self, history: List[Dict[str, Any]], user_message: str, context_refs: Dict[str, Any] = None) -> str:
        if not self.api_key:
            return "Error: OPENAI_API_KEY is not set in backend environment."

        # Gather live database context
        db_context = self._gather_context()

        system_prompt = (
            "You are the HexSniff Security Copilot. You are an expert Threat Hunter, Detection Engineer, and DFIR Analyst.\n"
            "CRITICAL RULES:\n"
            "1. NO HALLUCINATION. Do not invent packets, alerts, IPs, or cases.\n"
            "2. EVIDENCE ONLY. Every claim you make MUST be backed by the data provided below.\n"
            "3. CITE YOUR SOURCES. When discussing an alert, use its ID like [alert_id]. When discussing a chain, use [chain_id]. When discussing an asset, use [ip].\n"
            "4. You have FULL ACCESS to the network database. The current state of the network is provided below.\n"
            "5. DETECTION ENGINEERING. If asked to write a rule, output it in a code block marked with DRAFT ONLY.\n"
            "6. FORMAT. Use concise, structured Markdown.\n"
            "\n"
            "===== LIVE NETWORK TELEMETRY =====\n"
            f"{db_context}\n"
            "===== END TELEMETRY =====\n"
            "\n"
            "Use ONLY the data above to answer. If no relevant data exists, say so clearly."
        )

        messages = [{"role": "system", "content": system_prompt}]

        # Convert history
        for msg in history:
            role = "user" if msg["role"] == "user" else "assistant"
            messages.append({"role": role, "content": msg["content"]})

        # Append new user message
        prompt_text = user_message
        if context_refs:
            prompt_text += f"\n\n[System Auto-Context]: The user is currently looking at: {json.dumps(context_refs)}"
            
        messages.append({"role": "user", "content": prompt_text})

        url = f"{self.base_url.rstrip('/')}/chat/completions"
        
        payload = {
            "model": self.model,
            "messages": messages
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key.strip()}',
            'User-Agent': 'HexSniff/1.0'
        }
        req_obj = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers=headers,
            method='POST'
        )
        try:
            with urllib.request.urlopen(req_obj, timeout=30) as res:
                data = json.loads(res.read().decode())
                return data["choices"][0]["message"].get("content", "")
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode())
            except:
                body = {"error": f"HTTP Error {e.code}"}
            return f"API Error: {e.code} - {body}"
        except Exception as e:
            return f"Connection Error: {str(e)}"

copilot_engine = CopilotEngine()
