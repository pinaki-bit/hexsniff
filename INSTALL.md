# Installing HexSniff

HexSniff supports native deployment (best for live packet capture) and Docker deployment (best for offline Forensic Validation Labs and enterprise Linux environments).

---

## 🛠️ Prerequisites

1. **Python 3.12+**
2. **Node.js 20+**
3. **Npcap** (Windows only) or **libpcap / tcpdump** (Linux)
4. (Optional) **Docker Desktop**

---

## 🚀 Option 1: Native Installation (Recommended for Live Capture)

Because HexSniff captures raw network traffic directly from hardware interfaces, a native installation ensures full visibility into your actual network traffic.

### 1. Windows Setup
1. Download and install **Npcap** from [nmap.org/npcap](https://nmap.org/npcap/). Ensure you check "Install Npcap in WinPcap API-compatible Mode".
2. Clone the repository:
   ```bash
   git clone https://github.com/your-org/hexsniff.trim
   cd hexsniff
   ```

### 2. Linux Setup
1. Install network capture dependencies:
   ```bash
   sudo apt-get update
   sudo apt-get install libpcap-dev tcpdump
   ```
2. Clone the repository:
   ```bash
   git clone https://github.com/your-org/hexsniff.trim
   cd hexsniff
   ```

### 3. Launching the Backend (API & Detection Engine)
```bash
cd backend
python -m venv venv

# Activate venv (Windows)
.\venv\Scripts\activate
# Activate venv (Linux/Mac)
source venv/bin/activate

pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
> Note: On Linux, you must run uvicorn with `sudo` to capture live packets!

### 4. Launching the Frontend (React UI)
In a new terminal:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 🐳 Option 2: Docker Installation (Validation Lab / Offline Analysis)

> [!WARNING]
> **Docker Limitation on Windows/macOS:** Docker on Windows/Mac runs inside a virtual machine. This means the container can only "sniff" the internal VM network, not your host's physical Wi-Fi or Ethernet. Use Docker if you intend to use HexSniff purely as a PCAP analysis tool (Validation Lab), or if you are deploying to a native Linux server.

1. Ensure Docker and Docker Compose are installed.
2. Clone the repo and navigate to the project root.
3. Start the stack:
   ```bash
   docker-compose up -d --build
   ```
4. Access the UI at `http://localhost:5173`

*(If running on a native Linux host and you want live host network capture, uncomment `network_mode: "host"` in the `docker-compose.yml` file before running up).*

---

## ⚙️ Configuration (.env)

Copy the example configuration file:
```bash
cp .env.example .env
```

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key for the AI Analyst feature. | `""` |
| `BACKEND_PORT` | Port for FastAPI. | `8000` |
| `FRONTEND_PORT` | Port for the Vite UI. | `5173` |

Restart your application to apply `.env` changes.
