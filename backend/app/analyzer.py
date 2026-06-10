import os
import sys
import time
import re
from collections import defaultdict, deque
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

# DLL fix for Windows Npcap
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

from app.geoip import geoip_resolver
from app.ids_engine import IDSEngine

# Baseline regexes for empirical payload analysis
PASS_KEYWORDS = [
    re.compile(b"pass(word)?\\s*=\\s*[^&\\s]+", re.IGNORECASE),
    re.compile(b"usr\\s*=\\s*[^&\\s]+", re.IGNORECASE),
    re.compile(b"user(name)?\\s*=\\s*[^&\\s]+", re.IGNORECASE),
    re.compile(b"pwd\\s*=\\s*[^&\\s]+", re.IGNORECASE),
    re.compile(b"login_password\\s*=\\s*[^&\\s]+", re.IGNORECASE)
]

SQLI_KEYWORDS = [
    re.compile(b"union\\s+select", re.IGNORECASE),
    re.compile(b"select\\s+.*\\s+from", re.IGNORECASE),
    re.compile(b"'.*\\s+or\\s+.*=.*", re.IGNORECASE),
    re.compile(b"admin'\\s*--", re.IGNORECASE),
    re.compile(b"admin'\\s*#", re.IGNORECASE)
]

# Path Traversal patterns split by severity:
# HIGH — confirmed sensitive file access attempts (no HTTP context required)
PATH_TRAVERSAL_HIGH = re.compile(
    rb"/etc/passwd"
    rb"|/etc/shadow"
    rb"|/etc/hosts"
    rb"|/proc/self"
    rb"|\.\.\\\.\.\\",           # Windows ..\..\
    re.IGNORECASE
)
# Supplement HIGH with non-regex literals checked via `in` for win.ini / system32
PATH_TRAVERSAL_HIGH_LITERALS = [b"win.ini", b"system32", b"boot.ini"]

# MEDIUM — traversal sequences requiring HTTP context
PATH_TRAVERSAL_MEDIUM = re.compile(
    rb"(?:\.\.\/){2,}"          # ../../  (at least two hops)
    rb"|%2e%2e%2f"              # URL-encoded ../
    rb"|%252e%252e%252f"        # double URL-encoded (evasion)
    rb"|%2e%2e%5c"              # URL-encoded ..\
    rb"|%252e%252e%255c",       # double URL-encoded ..\
    re.IGNORECASE
)

# HTTP context markers — traversal only meaningful inside HTTP requests
HTTP_REQUEST_MARKERS = (
    b"GET /", b"POST /", b"PUT /", b"DELETE /",
    b"HEAD /", b"PATCH /", b"OPTIONS /",
    b"HTTP/1.", b"HTTP/2",
)

class PacketAnalyzer:
    def __init__(self):
        self.history_window = 10.0  # seconds
        self.packet_counter = 0
        self.beacon_track = defaultdict(deque)
        self.syn_track = defaultdict(deque)
        self.port_track = defaultdict(deque)
        self.alert_cooldowns = {} # Deduplication tracker
        
        # Initialize our Suricata and IOC engine
        self.ids_engine = IDSEngine()

    def check_ids_rules(self, packet_info: dict, payload: bytes) -> list:
        """Run legacy signature rules, rate-based checks, and the new Suricata/IOC rules."""
        alerts = []
        # Use authoritative packet timestamp to ensure temporal consistency in offline PCAP validation
        current_time = packet_info.get("timestamp", time.time())

        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        proto = packet_info.get("proto")

        if not src_ip or not dst_ip:
            return alerts

        # Helper to check if IP is private/internal
        def is_private_ip(ip: str) -> bool:
            if not ip:
                return False
            if ip.startswith("192.168.") or ip.startswith("10."):
                return True
            if ip.startswith("172."):
                try:
                    parts = ip.split('.')
                    if len(parts) >= 2:
                        second = int(parts[1])
                        return 16 <= second <= 31
                except ValueError:
                    pass
            return False

        # 1. Evaluate custom Suricata Rules & Threat Feed IOCs
        ids_alerts = self.ids_engine.run_checks(packet_info, payload)
        alerts.extend(ids_alerts)

        # 2. Legacy Payload-based checks (with added MITRE mappings)
        if payload:
            # Plaintext Credential Leak
            for kw in PASS_KEYWORDS:
                if kw.search(payload):
                    # Only add if not already caught by rules engine
                    if not any(a["mitre_technique"] == "T1552" for a in alerts):
                        alerts.append({
                            "id": f"alert_{self.packet_counter}_cred",
                            "severity": "High",
                            "category": "Credential Leak",
                            "message": f"Plaintext credentials detected in payload from {src_ip} to {dst_ip}.",
                            "mitre_technique": "T1552",
                            "mitre_tactic": "Credential Access",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "proto": proto
                        })
                    break

            # SQL Injection attempts
            for kw in SQLI_KEYWORDS:
                if kw.search(payload):
                    if not any(a["mitre_technique"] == "T1190" for a in alerts):
                        alerts.append({
                            "id": f"alert_{self.packet_counter}_sqli",
                            "severity": "High",
                            "category": "SQL Injection",
                            "message": f"Possible SQL injection payload detected from {src_ip} to {dst_ip}.",
                            "mitre_technique": "T1190",
                            "mitre_tactic": "Initial Access",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "proto": proto
                        })
                    break

            # Directory/Path Traversal
            # Gate 1: must be TCP (HTTP lives on TCP; skip raw UDP/binary)
            # Gate 2: only evaluate if payload starts with or contains HTTP markers
            #         OR contains high-severity sensitive file targets
            # Gate 3: per-source cooldown to avoid alert floods
            is_http_payload = any(marker in payload[:32] for marker in HTTP_REQUEST_MARKERS)
            pt_alert_id = f"path_traversal_{src_ip}"

            if not any(a["mitre_technique"] == "T1083" for a in alerts):
                pt_on_cooldown = (
                    current_time - self.alert_cooldowns.get(pt_alert_id, 0) < 10.0
                )

                # Check high-severity patterns (file targets) — fire regardless of HTTP context
                high_regex_match = PATH_TRAVERSAL_HIGH.search(payload)
                high_literal_match = next((lit for lit in PATH_TRAVERSAL_HIGH_LITERALS if lit in payload.lower()), None)
                high_match = high_regex_match or high_literal_match
                matched_str = (
                    high_regex_match.group(0).decode("utf-8", errors="replace")
                    if high_regex_match
                    else (high_literal_match.decode("utf-8", errors="replace") if high_literal_match else "")
                )
                if high_match and not pt_on_cooldown:
                    self.alert_cooldowns[pt_alert_id] = current_time
                    alerts.append({
                        "id": f"alert_{self.packet_counter}_traversal",
                        "severity": "High",
                        "category": "Path Traversal",
                        "message": (
                            f"Sensitive file target in payload from {src_ip} to {dst_ip}: "
                            f"matched pattern '{matched_str}'. T1083 exploitation attempt."
                        ),
                        "mitre_technique": "T1083",
                        "mitre_tactic": "Discovery",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "proto": proto
                    })
                # Check medium-severity traversal sequences — only within HTTP context
                elif is_http_payload and PATH_TRAVERSAL_MEDIUM.search(payload) and not pt_on_cooldown:
                    matched = PATH_TRAVERSAL_MEDIUM.search(payload).group(0).decode("utf-8", errors="replace")
                    self.alert_cooldowns[pt_alert_id] = current_time
                    alerts.append({
                        "id": f"alert_{self.packet_counter}_traversal",
                        "severity": "Medium",
                        "category": "Path Traversal",
                        "message": (
                            f"Directory traversal sequence in HTTP request from {src_ip} to {dst_ip}: "
                            f"'{matched}' detected in request payload."
                        ),
                        "mitre_technique": "T1083",
                        "mitre_tactic": "Discovery",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "proto": proto
                    })

            # Malware C2 command signatures
            c2_keywords = [b"cmd=", b"run_cmd", b"shell", b"exec=", b"download_agent", b"c2_server"]
            if any(k in payload for k in c2_keywords):
                if not any(a["mitre_technique"] == "T1071" for a in alerts):
                    alerts.append({
                        "id": f"alert_{self.packet_counter}_c2",
                        "severity": "Critical",
                        "category": "Malware C2 Command",
                        "message": f"Malware C2 communication command detected from {src_ip} to {dst_ip}.",
                        "mitre_technique": "T1071",
                        "mitre_tactic": "Command and Control",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "proto": proto
                    })

        # 3. DNS Tunneling detection
        dns_query = packet_info.get("dns_query")
        if dns_query and proto == "DNS":
            clean_q = dns_query.rstrip('.')
            parts = clean_q.split('.')
            if len(parts) > 0 and (len(parts[0]) > 25 or "tunnel" in clean_q or "exfil" in clean_q):
                alerts.append({
                    "id": f"alert_{self.packet_counter}_dns_tunnel",
                    "severity": "High",
                    "category": "DNS Tunneling",
                    "message": f"Potential DNS Tunneling (data exfiltration) detected in query: {dns_query}.",
                    "mitre_technique": "T1071.004",
                    "mitre_tactic": "Command and Control",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": proto
                })

        # 4. Beaconing detection
        # ── False Positive Suppression ─────────────────────────────────────────
        # The following destination IPs / ports are known multicast, broadcast,
        # and link-local protocols that fire at regular intervals and are NOT
        # indicative of C2 beaconing:
        #   239.255.255.250:1900  - SSDP (Simple Service Discovery Protocol)
        #   224.0.0.251:5353      - mDNS (Multicast DNS)
        #   224.0.0.252:5355      - LLMNR (Link-Local Multicast Name Resolution)
        #   255.255.255.255:67/68 - DHCP broadcast
        #   224.0.0.0/4           - All IPv4 multicast range
        BEACON_SUPPRESSED_DESTINATIONS = {
            "239.255.255.250",  # SSDP
            "224.0.0.251",      # mDNS
            "224.0.0.252",      # LLMNR
            "255.255.255.255",  # Broadcast (DHCP, etc.)
        }
        BEACON_SUPPRESSED_PORTS = {
            1900,   # SSDP
            5353,   # mDNS
            5355,   # LLMNR
            67,     # DHCP server
            68,     # DHCP client
        }

        dst_port_for_beacon = packet_info.get("dst_port")

        def is_multicast_ip(ip: str) -> bool:
            """True for 224.0.0.0/4 IPv4 multicast range."""
            try:
                first_octet = int(ip.split(".")[0])
                return 224 <= first_octet <= 239
            except (ValueError, IndexError):
                return False

        # Only evaluate beaconing on TCP/UDP to non-suppressed destinations
        beacon_eligible = (
            proto in ("TCP", "UDP")
            and dst_ip not in BEACON_SUPPRESSED_DESTINATIONS
            and dst_port_for_beacon not in BEACON_SUPPRESSED_PORTS
            and not is_multicast_ip(dst_ip)     # drop entire 224.0.0.0/4 range
            and not is_private_ip(dst_ip)       # only flag outbound to public IPs
            and dst_ip != "N/A"
        )

        if beacon_eligible:
            track = self.beacon_track[(src_ip, dst_ip)]
            track.append(current_time)
            while len(track) > 5:
                track.popleft()

            # Require at least 5 packets (previously 4) with tight variance
            if len(track) >= 5:
                intervals = [track[i] - track[i-1] for i in range(1, len(track))]
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                # Interval 1–120s (C2 heartbeats), variance < 0.1 (very periodic)
                if 1.0 <= avg_interval <= 120.0 and variance < 0.1:
                    alerts.append({
                        "id": f"alert_{self.packet_counter}_beacon",
                        "severity": "Medium",
                        "category": "Beaconing Detection",
                        "message": (
                            f"Periodic outbound beaconing to public IP {dst_ip} "
                            f"({avg_interval:.1f}s avg interval, variance={variance:.3f}). "
                            f"Possible C2 heartbeat from {src_ip}."
                        ),
                        "mitre_technique": "T1071",
                        "mitre_tactic": "Command and Control",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "proto": proto
                    })

        # 5. Lateral Movement detection
        dst_port = packet_info.get("dst_port")
        if is_private_ip(src_ip) and is_private_ip(dst_ip) and dst_port in (22, 445, 3389, 5985, 5986):
            alerts.append({
                "id": f"alert_{self.packet_counter}_lateral",
                "severity": "High",
                "category": "Lateral Movement",
                "message": f"Suspicious lateral movement attempt: admin connection ({proto} port {dst_port}) between internal hosts {src_ip} and {dst_ip}.",
                "mitre_technique": "T1021",
                "mitre_tactic": "Lateral Movement",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": proto
            })

        # 6. Rate and Protocol-based rules (SYN Flood, Port Scan)
        tcp_flags = packet_info.get("tcp_flags", "")

        # SYN Flood: count bare SYN (not SYN-ACK) packets from this source in the window.
        if proto == "TCP" and "S" in tcp_flags and "A" not in tcp_flags:
            st = self.syn_track[src_ip]
            st.append(current_time)
            while st and current_time - st[0] > self.history_window:
                st.popleft()

            if len(st) > 150:
                alert_id = f"syn_flood_{src_ip}"
                if current_time - self.alert_cooldowns.get(alert_id, 0) > 10.0:
                    self.alert_cooldowns[alert_id] = current_time
                    alerts.append({
                        "id": alert_id,
                        "severity": "High",
                        "category": "SYN Flood DDoS",
                        "message": f"SYN Flood detected from {src_ip}: {len(st)} bare SYNs in {self.history_window}s window.",
                        "mitre_technique": "T1498.001",
                        "mitre_tactic": "Impact",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "proto": proto
                    })

        # Port Scan: count unique destination ports from this source in the window.
        if proto in ("TCP", "UDP") and dst_port is not None:
            pt = self.port_track[src_ip]
            pt.append((current_time, dst_port))
            while pt and current_time - pt[0][0] > self.history_window:
                pt.popleft()

            scanned_ports = {port for _, port in pt}
            if len(scanned_ports) > 40:
                alert_id = f"port_scan_{src_ip}"
                if current_time - self.alert_cooldowns.get(alert_id, 0) > 10.0:
                    self.alert_cooldowns[alert_id] = current_time
                    alerts.append({
                        "id": alert_id,
                        "severity": "Medium",
                        "category": "Port Scanning",
                        "message": f"Port scanning from {src_ip}: {len(scanned_ports)} unique dst ports in {self.history_window}s.",
                        "mitre_technique": "T1046",
                        "mitre_tactic": "Reconnaissance",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "proto": proto
                    })

        return alerts

    def analyze_packet(self, packet: Packet) -> dict:
        """Parses a Scapy packet into a web-friendly enriched JSON structure."""
        self.packet_counter += 1
        
        packet_id = f"pkt_{self.packet_counter}"
        pkt_time = float(packet.time) if packet.time else time.time()
        pkt_len = len(packet)

        proto = "Other"
        src_ip = "N/A"
        dst_ip = "N/A"
        src_mac = "N/A"
        dst_mac = "N/A"
        src_port = None
        dst_port = None
        
        tcp_flags = ""
        dns_query = None
        summary = ""

        # Layer 2: Ethernet
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        # Layer 3: IPv4 / IPv6 / ARP
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "IPv4"
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            proto = "IPv6"
        elif ARP in packet:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            src_mac = packet[ARP].hwsrc
            dst_mac = packet[ARP].hwdst
            proto = "ARP"
            op = "request" if packet[ARP].op == 1 else "reply" if packet[ARP].op == 2 else str(packet[ARP].op)
            summary = f"ARP {op}: {src_ip} -> {dst_ip}"

        # Layer 4: TCP / UDP / ICMP
        payload_bytes = b""
        
        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            flag_list = []
            if flags & 0x01: flag_list.append("FIN")
            if flags & 0x02: flag_list.append("SYN")
            if flags & 0x04: flag_list.append("RST")
            if flags & 0x08: flag_list.append("PSH")
            if flags & 0x10: flag_list.append("ACK")
            if flags & 0x20: flag_list.append("URG")
            tcp_flags = "".join(f[0] for f in flag_list)
            
            flag_str = f" [{','.join(flag_list)}]" if flag_list else ""
            summary = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port}{flag_str}"
            
            if packet[TCP].payload:
                payload_bytes = bytes(packet[TCP].payload)

        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            summary = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            
            if packet[UDP].payload:
                payload_bytes = bytes(packet[UDP].payload)

            # Check if DNS
            if packet.haslayer("DNS") and packet["DNS"].qr == 0:
                proto = "DNS"
                try:
                    qname = packet["DNS"].qd.qname.decode('utf-8', errors='ignore')
                    dns_query = qname
                    summary = f"DNS Query: {qname} from {src_ip}"
                except Exception:
                    summary = f"DNS Query from {src_ip}"

        elif ICMP in packet:
            proto = "ICMP"
            itype = packet[ICMP].type
            icode = packet[ICMP].code
            type_str = "Request" if itype == 8 else "Reply" if itype == 0 else f"Type {itype}"
            summary = f"ICMP Echo {type_str}: {src_ip} -> {dst_ip}"
            if packet[ICMP].payload:
                payload_bytes = bytes(packet[ICMP].payload)

        # Fallback summary
        if not summary:
            summary = f"{proto} Packet: {src_ip} -> {dst_ip} (Len={pkt_len})"

        # HTTP Host extraction
        http_host = None
        if payload_bytes and proto == "TCP":
            try:
                if b"HTTP/" in payload_bytes[:30] or b"GET " in payload_bytes[:10] or b"POST " in payload_bytes[:10]:
                    match = re.search(br"(?i)Host:\s*([^\r\n]+)", payload_bytes)
                    if match:
                        http_host = match.group(1).decode("utf-8").strip()
            except Exception:
                pass

        # Clean payload display formats
        hex_dump = ""
        ascii_dump = ""
        if payload_bytes:
            hex_lines = []
            ascii_lines = []
            payload_to_dump = payload_bytes[:256]  # Limit to 256 bytes for performance
            for i in range(0, len(payload_to_dump), 16):
                chunk = payload_to_dump[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                hex_lines.append(f"{i:04x}   {hex_part:<47}")
                ascii_lines.append(ascii_part)
            hex_dump = "\n".join(hex_lines)
            ascii_dump = "\n".join(ascii_lines)

        # ── Geo-IP Lookup enrichment ──
        src_geo = geoip_resolver.lookup(src_ip)
        dst_geo = geoip_resolver.lookup(dst_ip)

        packet_info = {
            "id": packet_id,
            "timestamp": pkt_time,
            "length": pkt_len,
            "proto": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "dns_query": dns_query,
            "http_host": http_host,
            "summary": summary,
            "hex_dump": hex_dump,
            "ascii_dump": ascii_dump,
            "src_geo": src_geo,
            "dst_geo": dst_geo,
            "alerts": []
        }

        # Run IDS alerts
        alerts = self.check_ids_rules(packet_info, payload_bytes)
        packet_info["alerts"] = alerts

        return packet_info
