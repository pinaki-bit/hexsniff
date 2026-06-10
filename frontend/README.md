# HexSniff Frontend

This is the user interface for the **HexSniff NDR** platform. It is a highly optimized, single-page application (SPA) built to render real-time network traffic and cyber-security telemetry without dropping frames.

## 🛠️ Technology Stack

*   **Core:** React 19 + TypeScript
*   **Build Tool:** Vite (for Lightning-fast HMR and optimized production builds)
*   **Styling:** Tailwind CSS (v4) with custom cyberpunk UI tokens (Neon blue, Crimson, Void black).
*   **State Management:** Zustand (Used for low-latency, global state synchronization of incoming packet streams).
*   **Animations:** Framer Motion (for liquid-smooth layout transitions and micro-interactions).
*   **Visualizations:**
    *   **MapLibre GL:** For the geographic "Threat Orbit" map.
    *   **D3.js:** For the force-directed "Topology Scan" network graphs.
    *   **Chart.js / react-chartjs-2:** For the real-time "Data Telem" charts.
    *   **Three.js / React Three Fiber:** For the 3D WebGL Threat Globe.

## 📂 Directory Structure

```text
src/
├── assets/        # Static assets like icons and logos
├── components/    # Reusable UI components
│   ├── layout/    # TopBar, Sidebar, and StatusBar
│   └── Visuals/   # Complex 3D and 2D visualization components
├── pages/         # Top-level route components (Dashboard, ThreatMap, etc.)
├── store.ts       # Global Zustand state (Packet buffers, Alerts, WebSocket handling)
├── App.tsx        # Main application router and layout wrapper
├── index.css      # Tailwind directives and custom CSS variables
└── main.tsx       # React DOM entry point
```

## 🚀 Getting Started

To run the frontend in development mode:

1. Ensure you have Node.js (v18+) installed.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
4. Open your browser to `http://localhost:5173`.

> **Note:** The frontend requires the Python FastAPI backend to be running on `http://127.0.0.1:8000` in order to receive live packet data via WebSockets.

## 📡 WebSocket Integration

The entire UI is driven by a single, high-throughput WebSocket connection managed inside `store.ts`. 
*   **Event Buffer:** Incoming packets are buffered and flushed to the React state at 60Hz to prevent React re-render throttling.
*   **Live Mode:** When the backend is capturing packets, the UI dynamically shifts into a "Live" state, rendering packets into the Packet Matrix and updating charts on the fly.

## 🎨 UI/UX Design Philosophy

The HexSniff UI is designed to feel like a premium, military-grade Security Operations Center. 
*   **Color Palette:** Deep dark backgrounds (`#05080f`) contrasted with bright neon accents (cyan, magenta, emerald) to highlight actionable intelligence.
*   **Glassmorphism:** Subtle background blurring on panels to create depth.
*   **Monospace Typography:** Extensive use of monospace fonts for IPs, MAC addresses, and raw packet dumps to ensure forensic readability.
