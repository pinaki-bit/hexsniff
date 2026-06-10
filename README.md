<div align="center">
  <h1>HexSniff NDR</h1>
  <p><strong>Enterprise Network Detection & Response Platform</strong></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
  [![React](https://img.shields.io/badge/React-Vite-blueviolet.svg)](https://reactjs.org/)
</div>

---

## 🌟 What is HexSniff?

**HexSniff** is a premium, open-source Security Operations Center (SOC) and Network Detection and Response (NDR) platform. It serves as an all-in-one cyber-security suite that allows users to monitor their network traffic in real-time, detect malicious threats instantly, and analyze network packets with forensic precision. 

By combining raw packet capturing capabilities with advanced Threat Intelligence feeds and cutting-edge Artificial Intelligence (Google Gemini / Groq), HexSniff turns an overwhelming flood of network data into beautiful, actionable, and human-readable insights.

---

## ✨ Key Technical Features
*   **O(1) Detection Engine:** Sustains 1,800+ packets per second (PPS) in Python by utilizing strictly bounded algorithmic connections and hash-map IOC lookups. Highly resilient against SYN Floods and DDoS attacks.
*   **MITRE ATT&CK Mapping:** Automatic correlation of raw packet payloads to MITRE techniques (e.g., T1083, T1071) based on behavioral signatures.
*   **Dynamic Threat Intel:** Live synchronization with global security feeds like URLhaus and Feodo Tracker.
*   **Zero-Latency WebSockets:** Event-driven architecture that flushes UI updates at 60Hz without throttling the main capture thread.

---

## 🏗️ How it was Made & What was Needed

HexSniff was built using a decoupled architecture separating the high-speed packet capture engine from the dynamic visual interface.

### The Tech Stack
*   **Backend Engine (Python 3.12):** Built using `FastAPI` for blazing fast asynchronous API endpoints, `Scapy` and `Npcap` for raw network packet interception, and `SQLite` (with WAL mode) for rapid local storage.
*   **Frontend Interface (React + Vite):** A highly reactive dashboard built using `TypeScript`, `Tailwind CSS`, and `Framer Motion` for smooth cyberpunk-themed animations.
*   **Visualizations:** Powered by `D3.js` for force-directed topology graphs, `Chart.js` for analytics, and `MapLibre GL` for geographical mapping.

### What Was Needed to Make It
*   **Packet Drivers:** `Npcap` (Windows) or `libpcap` (Linux) to physically intercept traffic directly from the Network Interface Card (NIC) before it hits the operating system firewall.
*   **Offline GeoIP Databases:** MaxMind offline `.mmdb` files to map IP addresses to physical real-world locations without relying on slow web APIs.
*   **AI Integration:** API keys from Groq or Google Gemini to power the "AI Overseer," which translates raw packet payloads (Hex dumps) into human-readable analysis.

---

## 🎯 What Will the Application Do?

When you run HexSniff, it acts as a silent guardian over your network interface. It will:
1.  **Intercept Everything:** Capture every single piece of data (TCP, UDP, ICMP) entering or leaving your computer.
2.  **Correlate Threats:** Automatically cross-reference every IP address and payload against known Threat Intelligence databases (URLhaus, Feodo Tracker).
3.  **Map the World:** Extract IP addresses and instantly plot them on a geographic map, showing you exactly what countries your computer is communicating with.
4.  **Visualize the Network:** Build a spider-web graph of your local network, mapping out who is talking to who.
5.  **Explain with AI:** Allow you to click on any suspicious packet and have an AI instantly explain what the payload means and whether it is dangerous.

---

## 🕹️ How to Use the Application

1.  **Start the Backend:** Navigate to the `backend/` folder, activate the python virtual environment, and run the server using `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`.
2.  **Start the Frontend:** Navigate to the `frontend/` folder and run `npm run dev` to launch the React interface.
3.  **Open the Dashboard:** Open your browser to `http://localhost:5173`.
4.  **Begin Capture:** On the dashboard, select your active Network Interface (e.g., your Wi-Fi adapter) from the dropdown and click **Start Live Capture**.
5.  **Analyze:** Watch the dashboard light up with live traffic, and navigate through the sidebar to explore different security modules.

---

## 🎛️ Purpose of Every Button / Module

Here is exactly what every section of the application does:

### The Sidebar Navigation
*   **DASHBOARD:** The main command center. Displays high-level stats, total packets intercepted, active threats, and live protocol distribution charts.
*   **PACKET MATRIX (Analyzer):** A raw, scrolling terminal-like view of every single packet. Click on a packet to view its raw Hex dump and payload.
*   **THREAT ORBIT (Threat Map):** A 2D interactive world map. It plots the physical geographic location of every public IP address your computer communicates with.
*   **AI OVERSEER:** The integrated AI chat assistant. You can ask it questions about your network status, or click "Analyze with AI" on a specific packet to have it explain the threat.
*   **TOPOLOGY SCAN:** Generates a real-time spider-web graph of your network. Shows how your machine connects to the router and external servers. Click "Execute Sweep" to scan your local subnet for other devices.
*   **DATA TELEM (Analytics):** Deep-dive graphs and charts showing bandwidth usage, top talkers, and protocol breakdowns over time.
*   **THREAT INTEL:** Your local database of known bad actors. Shows the active synchronization status with global threat feeds.
*   **ASSET INV (Inventory):** A list of all unique IP addresses and MAC addresses detected on your network.
*   **FORENSICS (Investigation):** A workspace where you can group related suspicious packets together into a "Case" and write notes for incident response.
*   **THREAT HUNT:** Allows you to write custom detection rules (like Suricata/Snort rules) to trigger custom alerts when specific traffic patterns are seen.
*   **DETECTION LAB:** An offline testing environment. Upload a `.pcap` file (a recording of network traffic) and test your custom rules against it safely.
*   **SIG ENGINE:** Edit your system-wide detection signatures.
*   **CASE MGMT:** View and export your ongoing forensic investigations.
*   **EXPORT SYS (Reports):** Generate downloadable PDF or JSON reports of your network's health and recent security alerts.

### Key Actions
*   **Start Live Capture:** Hooks into your network card and begins intercepting live data.
*   **Stop Capture:** Halts the interception engine safely.
*   **Execute Sweep (Topology):** Sends out ARP broadcasts to actively discover hidden devices on your Wi-Fi.
*   **Ask AI / Analyze:** Sends packet payloads to Google Gemini / Groq for human-readable summaries.

---

## 🌍 How HexSniff Can Be Useful to People

1.  **For Everyday Users:** Have you ever wondered what your computer is doing in the background? HexSniff allows everyday users to see exactly which apps are sending data, where in the world that data is going, and if any background processes are secretly communicating with malicious servers.
2.  **For Students & Educators:** It serves as a highly visual, interactive learning tool for understanding how the internet works, how packets are structured, and how cyber attacks are executed.
3.  **For IT Professionals & Blue Teams:** It acts as a lightweight, deployable Network Intrusion Detection System (NIDS) that can be installed on a server to monitor traffic for anomalous behavior, unauthorized lateral movement, or data exfiltration without expensive enterprise licenses.

---

## 📈 Performance Benchmarks
*   **Peak Sustained PPS:** ~1,800 Packets/Sec (Single Core Python)
*   **Database Write Latency:** < 2.0 ms/op (WAL Mode)
*   **GeoIP Lookup Latency:** < 0.01 ms (LRU Cache)
*   **Threat Intel Matching:** O(1) Time Complexity

---

## 🚀 The Future: Making HexSniff More Powerful

HexSniff is a strong foundation, but its potential is limitless. Future roadmaps could include:

1.  **Automatic Attack Blocking (IPS):** Upgrading HexSniff from a Detection system (NDR) to a Prevention system (IPS) by actively injecting TCP RST (Reset) packets to kill malicious connections the moment they are detected.
2.  **SSL/TLS Decryption:** Currently, encrypted HTTPS payloads cannot be read. By implementing a local Man-in-The-Middle (MITM) proxy and installing a custom root certificate, HexSniff could decrypt, analyze, and re-encrypt secure traffic to find hidden malware.
3.  **Distributed Sensor Network:** Allowing users to install lightweight "HexSniff Agents" on multiple computers or cloud servers, all feeding telemetry back to a centralized HexSniff master dashboard for global enterprise monitoring.
4.  **Machine Learning Anomaly Detection:** Instead of relying just on static rules and AI chat, training a local ML model on your normal daily traffic behavior so it can automatically flag "weird" behavior (e.g., a smart bulb suddenly sending 5GB of data at 3 AM).
5.  **Active Response Automations:** Integrating with firewalls (like Windows Defender or iptables) so that if HexSniff detects a threat, it can automatically ban the IP address system-wide without human intervention.
