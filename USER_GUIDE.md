# HexSniff User Guide

Welcome to HexSniff, an enterprise-grade Network Detection & Response (NDR) platform.

## 📡 1. Live Packet Capture
Navigate to the **Dashboard**.
- Select a network interface from the dropdown.
- Click **Start Capture**.
- Live packets and security alerts will stream into the UI via WebSockets.
- *Performance Note:* The WebGL Threat Globe dynamically plots traffic in real-time.

## 🧪 2. Validation Lab (PCAP Analysis)
If you have captured suspicious traffic in a `.pcap` or `.pcapng` file using Wireshark or tcpdump:
- Navigate to the **Validation Lab**.
- Upload your `.pcap` file.
- HexSniff will offline-parse the file and map every anomalous packet against its Threat Intel and MITRE ATT&CK coverage engine, generating a highly structured Forensic Report.

## ⏪ 3. Replay Engine
To simulate live traffic for testing or demonstrations:
- Go to the **Replay** tab.
- Upload a `.pcap` file and select a playback speed (1x to 10x).
- The engine will stream the offline packets to the UI, simulating realistic timing intervals for detection validations.

## 🤖 4. AI Analyst
HexSniff integrates an LLM-powered AI Analyst (Google Gemini).
- From any Investigation Workspace or after a live capture session, click **AI Analyst**.
- The AI will ingest the current session's IDS alerts, evidence packets, and MITRE mapping data to generate an Executive Summary, Threat Findings, and Evidence-Based Recommendations.
- *Note:* Requires `GEMINI_API_KEY` in `.env`.

## 💼 5. Case Management
When a suspicious indicator is confirmed:
- Click the **Create Case** button on the alert.
- Assign a Title, Severity, and Status.
- From the **Case Management** tab, you can track investigations, attach specific Packet IDs as forensic evidence, and add investigative notes.

## 🛡️ 6. Threat Intel Feeds
HexSniff's IDS engine connects directly to URLhaus and Feodo Tracker.
- The platform automatically maps DNS queries and HTTP hosts against thousands of live Indicators of Compromise (IOCs).
- Lookups are strictly O(1) complexity, ensuring no latency penalty regardless of feed size.
