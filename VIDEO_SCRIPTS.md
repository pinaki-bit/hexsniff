# HexSniff Video Scripts (Portfolio Launch)

To successfully launch HexSniff as an open-source project and a portfolio centerpiece, visual demonstration is required. Because recruiters and engineers scroll fast, the hook must happen in the first 5 seconds.

## Video 1: The 2-Minute Demo (For LinkedIn & GitHub README)
**Goal:** Show, don't tell. Prove that it looks premium and works in real-time.

* **0:00 - 0:05 (The Hook):** Start on the **Threat Globe**. Do NOT start on the dashboard. Run a PCAP replay at 5x speed or start a live capture. Let the user see the 3D WebGL globe lighting up with neon connection arcs.
* **0:05 - 0:20 (The Dashboard):** Switch to the Dashboard. Highlight the PPS (Packets Per Second) counter hitting 1,000+. Call out the O(1) detection engine on screen (use a text overlay: `"Sustaining 1.5k PPS in Python via O(1) Hash Map Optimization"`).
* **0:20 - 0:40 (Threat Intel):** Show the Alerts tab. Hover over a Feodo Tracker IOC hit. Show the instant GeoIP enrichment.
* **0:40 - 1:10 (MITRE & AI Analyst):** Click "AI Analyst". Show the prompt generation and the Markdown output from Google Gemini explaining the attack chain.
* **1:10 - 1:40 (Case Management):** Click "Create Case". Show the SQLite persistence by adding a Packet ID as evidence. 
* **1:40 - 2:00 (Call to Action):** Show the Docker start command: `docker-compose up -d`. End with a link to the GitHub repository.

## Video 2: Technical Architecture Breakdown (For Interviews & YouTube)
**Goal:** Prove you didn't just glue APIs together. Explain the hard computer science problems you solved.

* **Section 1: The Python GIL Bottleneck.** Explain how Scapy usually blocks the event loop. Show your Architecture diagram. Explain the separation of the background thread (capturing raw bytes) and the async FastAPI event loop.
* **Section 2: Defeating O(N²).** Show the code block where typical sniffers loop over active connections. Show your `ConnectionTracker` using dictionaries. Explain: *"In an Nmap SYN flood, looping over a list of 50,000 connections takes exponential time. My O(1) hash map handles a SYN flood with zero CPU spikes."*
* **Section 3: The Frontend WebGL Bridge.** Explain the challenge of pushing thousands of DOM elements to React. Show how you bypassed React's DOM reconciliation by piping the WebSocket data directly into the React Three Fiber `useFrame` loop for 60 FPS rendering.
