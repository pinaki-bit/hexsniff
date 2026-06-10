import os
import re
import json
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Dict, Any, Optional

class IDSRule:
    def __init__(self, action: str, proto: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, options_str: str):
        self.action = action.lower()
        self.proto = proto.lower()
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.msg = ""
        self.content: List[str] = []
        self.nocase = False
        self.sid = 0
        self.mitre = None
        self.mitre_tactic = None
        self._parse_options(options_str)

    def _parse_options(self, opts: str):
        pattern = r'(\w+)\s*:\s*("[^"]*"|[^;]+)'
        matches = re.findall(pattern, opts)
        for key, val in matches:
            key = key.strip().lower()
            val = val.strip().strip('"')
            if key == 'msg':
                self.msg = val
            elif key == 'content':
                self.content.append(val)
            elif key == 'nocase':
                self.nocase = True
            elif key == 'sid':
                try:
                    self.sid = int(val)
                except ValueError:
                    pass
            elif key == 'reference':
                if val.startswith('mitre,'):
                    self.mitre = val.split(',')[1].strip()
            elif key == 'classtype':
                # Map some standard Suricata classtypes to MITRE if needed
                if val == 'trojan-activity' and not self.mitre:
                    self.mitre = "T1071"
                    self.mitre_tactic = "Command and Control"
                elif val == 'attempted-recon' and not self.mitre:
                    self.mitre = "T1595"
                    self.mitre_tactic = "Reconnaissance"
            elif key == 'mitre':
                self.mitre = val
            elif key == 'tactic':
                self.mitre_tactic = val

    def match(self, packet_info: Dict[str, Any], payload: bytes) -> bool:
        proto = packet_info.get("proto", "").lower()
        if self.proto != "any" and self.proto != proto:
            if self.proto in ("ip", "ipv4") and proto in ("tcp", "udp", "icmp", "ipv4"):
                pass
            else:
                return False

        dst_port = packet_info.get("dst_port")
        if self.dst_port != "any":
            try:
                d_port_rule = int(self.dst_port)
                if dst_port != d_port_rule:
                    return False
            except ValueError:
                pass

        src_port = packet_info.get("src_port")
        if self.src_port != "any":
            try:
                s_port_rule = int(self.src_port)
                if src_port != s_port_rule:
                    return False
            except ValueError:
                pass

        if self.content:
            if not payload:
                return False
            payload_to_search = payload.lower() if self.nocase else payload
            for content_str in self.content:
                pattern = content_str.lower().encode() if self.nocase else content_str.encode()
                if pattern not in payload_to_search:
                    return False

        return True


class IDSEngine:
    """
    IDS engine with Suricata-style rule matching and live threat feed IOC support.

    IOC sources (fetched by sync_feeds):
      - Feodo Tracker  : https://feodotracker.abuse.ch/downloads/ipblocklist.json  (no key)
      - URLhaus recent : https://urlhaus-api.abuse.ch/v1/urls/recent/              (no key)
    """

    def __init__(self, rules_path: str = "app/rules/ids.rules", ioc_path: str = "app/rules/ioc_list.json"):
        self.rules_path = rules_path
        self.ioc_path = ioc_path
        self.rules: List[IDSRule] = []
        self.iocs: List[Dict[str, Any]] = []
        self.ioc_ips: Dict[str, Dict[str, Any]] = {}
        self.ioc_domains: Dict[str, Dict[str, Any]] = {}
        self.ioc_urls: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._ensure_rule_file()
        self.load_rules()
        self.load_iocs()

    # ──────────────────────────────────────────────────────────────────────────
    # Bootstrap
    # ──────────────────────────────────────────────────────────────────────────

    def _ensure_rule_file(self):
        """Create the rules directory and a default IDS signature file if absent."""
        os.makedirs(os.path.dirname(self.rules_path), exist_ok=True)

        if not os.path.exists(self.rules_path):
            default_rules = (
                "# Suricata-style IDS rules for HexSniff\n"
                'alert tcp any any -> any 80 (msg:"SQL Injection Attempt - UNION SELECT"; content:"union select"; nocase; sid:100001; mitre:T1190; tactic:Initial Access;)\n'
                'alert tcp any any -> any 80 (msg:"SQL Injection Attempt - OR 1=1"; content:"or 1=1"; nocase; sid:100002; mitre:T1190; tactic:Initial Access;)\n'
                'alert tcp any any -> any 80 (msg:"SQL Injection Attempt - UNION ALL"; content:"union all select"; nocase; sid:100003; mitre:T1190; tactic:Initial Access;)\n'
                'alert tcp any any -> any 80 (msg:"Path Traversal Attempt - /etc/passwd"; content:"../etc/passwd"; nocase; sid:100004; mitre:T1083; tactic:Discovery;)\n'
                'alert tcp any any -> any 80 (msg:"Path Traversal Attempt - win.ini"; content:"win.ini"; nocase; sid:100005; mitre:T1083; tactic:Discovery;)\n'
                'alert tcp any any -> any 80 (msg:"Plaintext Password Transmission"; content:"password="; nocase; sid:100006; mitre:T1552; tactic:Credential Access;)\n'
                'alert tcp any any -> any 80 (msg:"Plaintext Credential exposure in URL"; content:"pwd="; nocase; sid:100007; mitre:T1552; tactic:Credential Access;)\n'
                'alert tcp any any -> any 21 (msg:"Insecure FTP Login Command"; content:"USER"; nocase; sid:100008; mitre:T1552; tactic:Credential Access;)\n'
                'alert tcp any any -> any 23 (msg:"Insecure Telnet Connection Request"; content:"login:"; nocase; sid:100009; mitre:T1021; tactic:Lateral Movement;)\n'
                'alert tcp any any -> any any (msg:"Malware C2 Command execution signature"; content:"run_cmd"; nocase; sid:100010; mitre:T1071; tactic:Command and Control;)\n'
                'alert tcp any any -> any any (msg:"Malware C2 Command - agent download"; content:"download_agent"; nocase; sid:100011; mitre:T1071; tactic:Command and Control;)\n'
                'alert tcp any any -> any any (msg:"Malware C2 Server Communication Link"; content:"c2_server"; nocase; sid:100012; mitre:T1071; tactic:Command and Control;)\n'
            )
            with open(self.rules_path, 'w', encoding='utf-8') as f:
                f.write(default_rules)

        # IOC file starts empty — real indicators come from sync_feeds()
        if not os.path.exists(self.ioc_path):
            with open(self.ioc_path, 'w', encoding='utf-8') as f:
                json.dump([], f)

    # ──────────────────────────────────────────────────────────────────────────
    # Load / Reload
    # ──────────────────────────────────────────────────────────────────────────

    def load_rules(self):
        self.rules = []
        try:
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    match = re.match(
                        r'^(\w+)\s+(\w+|any)\s+([a-zA-Z0-9_\/\.\*]+?|any)\s+([a-zA-Z0-9_\.]+?|any)\s+->\s+([a-zA-Z0-9_\/\.\*]+?|any)\s+([a-zA-Z0-9_\.]+?|any)\s+\((.*)\)',
                        line
                    )
                    if match:
                        action, proto, src_ip, src_port, dst_ip, dst_port, options = match.groups()
                        self.rules.append(IDSRule(action, proto, src_ip, src_port, dst_ip, dst_port, options))
        except Exception as e:
            print(f"[IDSEngine] Error loading rules: {e}")

    def get_rules_content(self) -> str:
        """Returns the raw content of the ids.rules file."""
        try:
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"[IDSEngine] Error reading rules file: {e}")
            return ""

    def save_rules_content(self, content: str) -> bool:
        """Saves new content to the ids.rules file and reloads the engine."""
        try:
            with open(self.rules_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self.load_rules()
            return True
        except Exception as e:
            print(f"[IDSEngine] Error saving rules file: {e}")
            return False

    def load_iocs(self):
        with self._lock:
            try:
                with open(self.ioc_path, 'r', encoding='utf-8') as f:
                    self.iocs = json.load(f)
                    self._rebuild_ioc_maps()
            except Exception as e:
                print(f"[IDSEngine] Error loading IOCs: {e}")
                self.iocs = []
                self._rebuild_ioc_maps()

    def _rebuild_ioc_maps(self):
        self.ioc_ips.clear()
        self.ioc_domains.clear()
        self.ioc_urls.clear()
        for ioc in self.iocs:
            val = ioc.get("value", "").lower()
            itype = ioc.get("type", "").upper()
            if itype == "IP":
                self.ioc_ips[val] = ioc
            elif itype == "DOMAIN":
                self.ioc_domains[val] = ioc
            elif itype == "URL":
                self.ioc_urls[val] = ioc

    def reload_iocs(self):
        """Thread-safe hot reload of the IOC list from disk."""
        self.load_iocs()

    # ──────────────────────────────────────────────────────────────────────────
    # Live Threat Feed Ingestion
    # ──────────────────────────────────────────────────────────────────────────

    def sync_feeds(self) -> Dict[str, Any]:
        """
        Fetches real IOCs from public threat intelligence feeds (no API key required).

        Feeds:
          - Feodo Tracker C2 IP blocklist (Emotet / Qakbot / TrickBot / Pikabot)
          - URLhaus recent malware distribution URLs

        Returns a summary dict with counts and any errors.
        """
        fetched_iocs: List[Dict[str, Any]] = []
        errors: List[str] = []
        now_ts = int(time.time())

        # ── 1. Feodo Tracker – C2 IP blocklist ────────────────────────────────
        try:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
            req = urllib.request.Request(url, headers={"User-Agent": "HexSniff-NDR/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            feodo_count = 0
            for entry in data:
                ip = entry.get("ip_address", "").strip()
                if not ip:
                    continue
                malware = entry.get("malware", "Unknown")
                country = entry.get("country", "")
                port = entry.get("port")
                status = entry.get("status", "unknown")
                ioc = {
                    "id": f"feodo-{ip.replace('.', '-')}",
                    "value": ip,
                    "type": "IP",
                    "severity": "Critical",
                    "source": "Feodo Tracker",
                    "description": (
                        f"{malware} C2 server ({status}). "
                        f"Country: {country}. "
                        f"Port: {port}."
                    ),
                    "mitre": "T1071.001",
                    "tags": [malware, "C2", "Botnet"],
                    "synced_at": now_ts,
                    "first_seen": now_ts,
                    "last_seen": now_ts,
                    "confidence": 95,
                    "active": True,
                    "hit_count": 0
                }
                fetched_iocs.append(ioc)
                feodo_count += 1

            print(f"[IDSEngine] Feodo Tracker: {feodo_count} C2 IPs ingested.")
        except Exception as e:
            msg = f"Feodo Tracker fetch failed: {e}"
            print(f"[IDSEngine] {msg}")
            errors.append(msg)

        # ── 2. URLhaus – malware distribution URLs ────────────────────────────
        urlhaus_count = 0
        import csv
        import io
        for attempt in range(3):
            try:
                url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "HexSniff-NDR/1.0"},
                    method="GET"
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    lines = resp.read().decode('utf-8').splitlines()
                
                # Parse CSV (skip comments starting with #)
                data_lines = [line for line in lines if not line.startswith('#')]
                reader = csv.reader(io.StringIO('\\n'.join(data_lines)))
                
                for row in reader:
                    # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
                    if len(row) < 7:
                        continue
                    url_val = row[2]
                    url_status = row[3]
                    threat = row[5]
                    tags_raw = [t.strip() for t in row[6].split(',')] if row[6] and row[6] != "None" else []
                    
                    if url_status != "online":
                        continue
                        
                    # Extract host from url (e.g. http://example.com/payload.exe -> example.com)
                    parsed = urllib.parse.urlparse(url_val)
                    host = parsed.netloc.split(':')[0]
                    if not host:
                        continue
                        
                    ioc = {
                        "id": f"urlhaus-{abs(hash(host)) % 10**9}",
                        "value": host,
                        "type": "Domain",
                        "severity": "High",
                        "source": "URLhaus",
                        "description": f"Malware distribution host (online). Threat: {threat}.",
                        "mitre": "T1105",
                        "tags": tags_raw[:3] if tags_raw else ["malware", "distribution"],
                        "synced_at": now_ts,
                        "first_seen": now_ts,
                        "last_seen": now_ts,
                        "confidence": 85,
                        "active": True,
                        "hit_count": 0
                    }
                    fetched_iocs.append(ioc)
                    urlhaus_count += 1
                    if urlhaus_count >= 200:
                        break
                break # Success, break out of retry loop
            except Exception as e:
                msg = f"URLhaus fetch failed (attempt {attempt+1}): {e}"
                print(f"[IDSEngine] {msg}")
                time.sleep(2)

            if attempt == 2:
                errors.append(msg)
                
        print(f"[IDSEngine] URLhaus: {urlhaus_count} distribution hosts ingested.")

        if not fetched_iocs and errors:
            return {"success": False, "errors": errors, "count": 0}

        # ── Deduplicate by indicator value and merge with existing ────────────
        with self._lock:
            existing_map = {ioc.get("value", "").lower(): ioc for ioc in self.iocs}
            
            for ioc in fetched_iocs:
                key = ioc["value"].lower()
                if key in existing_map:
                    # Update existing record (preserve first_seen and hit_count)
                    existing_map[key]["last_seen"] = now_ts
                    existing_map[key]["synced_at"] = now_ts
                    existing_map[key]["active"] = True
                else:
                    existing_map[key] = ioc

            unique_iocs = list(existing_map.values())

        # ── Persist to disk and hot-reload ─────────────────────────────────────
        try:
            with self._lock:
                with open(self.ioc_path, 'w', encoding='utf-8') as f:
                    json.dump(unique_iocs, f, indent=2)
                self.iocs = unique_iocs
                self._rebuild_ioc_maps()
        except Exception as e:
            msg = f"IOC file write failed: {e}"
            print(f"[IDSEngine] {msg}")
            errors.append(msg)

        return {
            "success": True,
            "count": len(unique_iocs),
            "errors": errors,
            "synced_at": now_ts,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Mutation helpers
    # ──────────────────────────────────────────────────────────────────────────

    def add_ioc(self, ioc: Dict[str, Any]):
        with self._lock:
            self.iocs.append(ioc)
            self._rebuild_ioc_maps()
            try:
                with open(self.ioc_path, 'w', encoding='utf-8') as f:
                    json.dump(self.iocs, f, indent=2)
            except Exception as e:
                print(f"[IDSEngine] Error writing IOCs: {e}")

    def import_iocs(self, new_iocs: List[Dict[str, Any]]) -> int:
        """Bulk imports IOCs, deduplicates by value, and saves to disk once."""
        with self._lock:
            existing_map = {ioc.get("value", "").lower(): ioc for ioc in self.iocs}
            added_count = 0
            
            for ioc in new_iocs:
                key = ioc.get("value", "").lower()
                if not key:
                    continue
                if key not in existing_map:
                    existing_map[key] = ioc
                    added_count += 1
                else:
                    # Merge/Update existing
                    existing_map[key].update(ioc)

            self.iocs = list(existing_map.values())
            self._rebuild_ioc_maps()
            
            try:
                with open(self.ioc_path, 'w', encoding='utf-8') as f:
                    json.dump(self.iocs, f, indent=2)
            except Exception as e:
                print(f"[IDSEngine] Error writing IOCs during bulk import: {e}")
                
            return added_count

    def update_ioc_history(self, ioc_id: str, timestamp: float):
        """Update last_seen and hit_count for an IOC when it triggers an alert."""
        with self._lock:
            updated = False
            for ioc in self.iocs:
                if ioc.get("id") == ioc_id:
                    ioc["last_seen"] = int(timestamp)
                    ioc["hit_count"] = ioc.get("hit_count", 0) + 1
                    updated = True
                    break
            
            if updated:
                try:
                    with open(self.ioc_path, 'w', encoding='utf-8') as f:
                        json.dump(self.iocs, f, indent=2)
                except Exception as e:
                    print(f"[IDSEngine] Error writing IOCs: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Runtime checks
    # ──────────────────────────────────────────────────────────────────────────

    def run_checks(self, packet_info: Dict[str, Any], payload: bytes) -> List[Dict[str, Any]]:
        alerts = []

        # 1. Evaluate Suricata Rules
        for rule in self.rules:
            if rule.match(packet_info, payload):
                alerts.append({
                    "id": f"alert_rule_{rule.sid}_{packet_info.get('id')}",
                    "severity": "High" if rule.mitre in ("T1190", "T1071") else "Medium",
                    "category": rule.msg,
                    "message": (
                        f"IDS rule SID {rule.sid} matched: {rule.msg} "
                        f"in payload from {packet_info.get('src_ip')} to {packet_info.get('dst_ip')}."
                    ),
                    "mitre_technique": rule.mitre,
                    "mitre_tactic": rule.mitre_tactic,
                    "src_ip": packet_info.get("src_ip"),
                    "dst_ip": packet_info.get("dst_ip"),
                    "proto": packet_info.get("proto")
                })

        # 2. Evaluate Dynamic Threat Feed IOCs
        src_ip = (packet_info.get("src_ip") or "").lower()
        dst_ip = (packet_info.get("dst_ip") or "").lower()
        dns_query = (packet_info.get("dns_query") or "").lower()
        http_host = (packet_info.get("http_host") or "").lower()

        with self._lock:
            # O(1) IP Check
            if src_ip in self.ioc_ips:
                alerts.append(self._generate_ioc_alert(self.ioc_ips[src_ip], packet_info))
            if dst_ip in self.ioc_ips and dst_ip != src_ip:
                alerts.append(self._generate_ioc_alert(self.ioc_ips[dst_ip], packet_info))
            
            # O(1) Domain Check (exact match on query)
            if dns_query in self.ioc_domains:
                alerts.append(self._generate_ioc_alert(self.ioc_domains[dns_query], packet_info))
            
            # O(1) URL/Host Check
            if http_host in self.ioc_urls:
                alerts.append(self._generate_ioc_alert(self.ioc_urls[http_host], packet_info))
            elif http_host in self.ioc_domains:
                alerts.append(self._generate_ioc_alert(self.ioc_domains[http_host], packet_info))

        return alerts

    def _generate_ioc_alert(self, ioc: Dict[str, Any], packet_info: Dict[str, Any]) -> Dict[str, Any]:
        conf = ioc.get("confidence", 90)
        return {
            "id": f"alert_ioc_{ioc.get('id')}_{packet_info.get('id')}",
            "severity": ioc.get("severity", "High"),
            "category": "Matched IOC Indicator",
            "message": (
                f"Threat Feed Alert: Packet matched known malicious "
                f"{ioc.get('type')}: {ioc.get('value')} "
                f"({ioc.get('source')}: {ioc.get('description')})."
            ),
            "mitre_technique": ioc.get("mitre", "T1071"),
            "mitre_tactic": ioc.get("tactic", "Command and Control"),
            "src_ip": packet_info.get("src_ip"),
            "dst_ip": packet_info.get("dst_ip"),
            "proto": packet_info.get("proto"),
            "ioc_hit": True,
            "ioc_id": ioc.get("id"),
            "ioc_value": ioc.get("value"),
            "ioc_type": ioc.get("type"),
            "source_feed": ioc.get("source"),
            "confidence": conf
        }
