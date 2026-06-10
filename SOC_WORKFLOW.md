# SOC Analyst Workflow Guide

HexSniff is designed to accelerate the incident response lifecycle. A typical Security Operations Center (SOC) workflow follows these steps:

### 1. Alert Generation (Triage)
- Monitor the **HexSniff Dashboard**.
- High-severity alerts (e.g., *Path Traversal*, *Malware C2 Beaconing*) appear in the active events feed.
- HexSniff automatically deduplicates connection spikes (like SYN Floods) into single actionable alerts.

### 2. Initial Investigation (Context)
- Click the alert to open the **Investigation Workspace**.
- Review the matched **MITRE ATT&CK Mapping** (e.g., `T1083 - File and Directory Discovery`).
- Identify the Source IP and Destination IP.
- Check the **Threat Globe** to visualize geographic origination.

### 3. IOC Analysis (Threat Intel)
- If the alert is an **IOC Hit**, verify the feed source (e.g., *Feodo Tracker*).
- HexSniff operates O(1) lookups, guaranteeing that the domain or IP is actively listed as malicious in current threat intelligence feeds.

### 4. Case Creation (Tracking)
- From the Alert panel, click **Create Case**.
- Set the severity to HIGH or CRITICAL.
- Assign a specific investigative title: e.g., `"Suspicious C2 Beaconing from 10.0.1.45"`.

### 5. Evidence Collection (Forensics)
- Open the packet details to view the **Hex Dump** and **ASCII Dump** of the malicious payload.
- In the Case Manager, select your active case and attach the specific `Packet ID` or `Alert ID`.
- This ensures the raw payload evidence is immutably linked to the case timeline.

### 6. AI Verification (Reporting)
- Execute the **AI Analyst** query.
- The AI will ingest the raw packets and alerts, parsing the metadata into a human-readable **Executive Summary**.
- Copy the AI's *Evidence-Based Recommendations* (e.g., Firewall block rules, WAF signatures) to hand off to the infrastructure or networking team for remediation.
