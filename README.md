<div align="center">
  <img src="frontend/public/favicon.ico" alt="HexSniff Logo" width="100"/>
  <h1>HexSniff NDR</h1>
  <p><strong>Enterprise Network Detection & Response Platform</strong></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
  [![React](https://img.shields.io/badge/React-Vite-blueviolet.svg)](https://reactjs.org/)
  [![Three.js](https://img.shields.io/badge/Three.js-WebGL-black.svg)](https://threejs.org/)
</div>

---

**HexSniff** is a premium, open-source Security Operations Center (SOC) platform designed for live packet capture, offline PCAP forensics, and automated threat hunting. Powered by an O(1) detection engine, dynamic threat intelligence, and AI-driven analysis, it brings enterprise-grade network visibility to your fingertips.

## ✨ Key Features
- **O(1) Detection Engine:** Sustains 1,800+ packets per second (PPS) in Python by utilizing strictly bounded algorithmic connections and hash-map IOC lookups. Resilient against SYN Floods and DDoS.
- **Dynamic Threat Intel:** Live synchronization with URLhaus and Feodo Tracker.
- **MITRE ATT&CK Mapping:** Automatic correlation of raw packet payloads to MITRE techniques (e.g., T1083, T1071).
- **WebGL Threat Globe:** Stunning real-time geographic visualization of live packet traffic using Three.js.
- **Forensic Validation Lab:** Upload PCAPs and run isolated detection suites to generate evidence-based incident reports.
- **AI Security Analyst:** Integrated with Google Gemini to generate human-readable executive summaries from raw packet hex dumps.
- **Case Management:** Built-in SQLite-backed investigation tracking.

## 📸 Platform Previews

### 1. Dashboard & Live WebGL Threat Globe
![Threat Globe Demo](docs/assets/threat_globe.gif)
*Real-time geographical tracking of inbound/outbound packets.*

### 2. Threat Map & GeoIP Enrichment
![Threat Map](docs/assets/threat_map.png)
*Detailed 2D map view with rolling connection histories.*

### 3. Investigation Workspace & PCAP Replay
![Investigation Workspace](docs/assets/investigation_workspace.png)
*Upload PCAPs for simulated replay or drill down into packet hex dumps.*

### 4. Google Gemini AI Analyst
![AI Analyst](docs/assets/ai_analyst.png)
*Automated forensic summaries directly from raw packet payloads.*

### 5. Detection Validation Lab
![Validation Lab](docs/assets/validation_lab.png)
*Execute offline forensic scans against large historical packet captures.*

## 🏛️ Architecture Overview
![Architecture Diagram](docs/assets/architecture.png)
*A high-level view of the decoupled, async-driven O(1) detection pipeline.*

## 🚀 Quick Start
HexSniff can be installed natively for live physical capture, or via Docker for forensic PCAP labs.

```bash
git clone https://github.com/your-org/hexsniff.trim
cd hexsniff
docker-compose up -d --build
```
> For complete instructions, including Native Windows/Linux deployment for live host capture, please see [INSTALL.md](INSTALL.md).

## 📖 Documentation
- [User Guide](USER_GUIDE.md) - Learn how to navigate the platform.
- [SOC Analyst Workflow](SOC_WORKFLOW.md) - How to use HexSniff for Incident Response.
- [Architecture](ARCHITECTURE.md) - Deep dive into the O(1) packet pipeline.

## 📈 Benchmarks (Phase 6)
- **Peak Sustained PPS:** ~1,800 Packets/Sec (Single Core Python)
- **Database Write Latency:** < 2.0 ms/op (WAL Mode)
- **GeoIP Lookup Latency:** < 0.01 ms (LRU Cache)
- **Threat Intel Matching:** O(1) Time Complexity

## 🤝 Contributing
We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before submitting Pull Requests.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
