import { useState, useEffect } from 'react';

export interface Alert {
  id: string;
  severity: 'High' | 'Medium' | 'Low' | 'Critical';
  category: string;
  message: string;
  timestamp?: number;
  packetId?: string;
  mitre_technique?: string;
  mitre_tactic?: string;
  confidence?: number;
  evidence_packets?: number;
  src_ip?: string;
  dst_ip?: string;
  first_seen?: number;
  last_seen?: number;
  ioc_hit?: boolean;
  ioc_id?: string;
  ioc_value?: string;
  ioc_type?: string;
  source_feed?: string;
  threat_score?: number;
  risk_level?: string;
}

export interface GeoData {
  country: string;
  code: string;
  city: string;
  lat: number | null;
  lon: number | null;
  asn?: string;
  isp?: string;
}

export interface PacketData {
  id: string;
  timestamp: number;
  length: number;
  proto: string;
  src_ip: string;
  dst_ip: string;
  src_mac: string;
  dst_mac: string;
  src_port: number | null;
  dst_port: number | null;
  tcp_flags: string;
  dns_query: string | null;
  summary: string;
  hex_dump: string;
  ascii_dump: string;
  src_geo?: GeoData;
  dst_geo?: GeoData;
  alerts: Alert[];
}

export interface NetworkInterface {
  name: string;
  description: string;
  ip: string;
  capture_capable?: boolean;
  guid?: string;
  npcap_available?: boolean;
}

export type CaptureMode = 'live' | 'replay' | null;

export interface CoverageTechnique {
  technique_id: string;
  tactic: string;
  detections: number;
  evidence_packets: number;
  validation_sessions: number;
  confidence_avg: number;
}

export interface RuleEffectiveness {
  rule_name: string;
  trigger_count: number;
  validation_hits: number;
  evidence_packets: number;
  confidence_avg: number;
  low_conf_count: number;
}

export interface ValidationHistoryEntry {
  session_id: string;
  date: number;
  detections: number;
  techniques: number;
  coverage_impact: number;
}

export interface CoverageStats {
  techniques: CoverageTechnique[];
  rules: RuleEffectiveness[];
  history: ValidationHistoryEntry[];
  coverage_by_tactic: Record<string, { techniques: number; evidence: number; detections: number }>;
  gaps: string[];
  total_validation_runs: number;
  fpr: number;
  total_low_confidence: number;
}

export interface HuntGraphData {
  nodes: { id: string; type: string; label: string; data?: any }[];
  edges: { source: string; target: string; label: string }[];
}

export interface StoreState {
  packets: PacketData[];
  alerts: Alert[];
  mode: CaptureMode;
  replaySpeed: number;
  activeInterface: string;
  interfaces: NetworkInterface[];
  totalPackets: number;
  packetRate: number;
  dataRate: number;
  timelineLabels: string[];
  timelineCounts: number[];
  protocolCounts: Record<string, number>;
  backendError: string | null;
  selectedPacket: PacketData | null;
  achievements: string[];
  coverageStats: CoverageStats | null;
  huntResults: any[];
  huntGraph: HuntGraphData | null;
  isHunting: boolean;
}

type Listener = () => void;

const MAX_PACKETS = 500;
const TIMELINE_LEN = 20;

class PacketStore {
  private state: StoreState = {
    packets: [],
    alerts: [],
    mode: null,
    replaySpeed: 1,
    activeInterface: '',
    interfaces: [],
    totalPackets: 0,
    packetRate: 0,
    dataRate: 0,
    timelineLabels: Array(TIMELINE_LEN).fill(''),
    timelineCounts: Array(TIMELINE_LEN).fill(0),
    protocolCounts: { TCP: 0, UDP: 0, DNS: 0, ICMP: 0, ARP: 0, Other: 0 },
    backendError: null,
    selectedPacket: null,
    achievements: JSON.parse(localStorage.getItem('hexsniff_achievements') || '[]'),
    coverageStats: null,
    huntResults: [],
    huntGraph: null,
    isHunting: false,
  };

  private listeners = new Set<Listener>();
  private socket: WebSocket | null = null;
  private rateInterval: number | null = null;
  private ppsAccum = 0;
  private bpsAccum = 0;
  private packetBuffer: PacketData[] = [];
  private flushInterval: number | null = null;

  subscribe(fn: Listener) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  getState(): StoreState {
    return this.state;
  }

  private emit() {
    this.listeners.forEach(fn => fn());
  }

  private patch(partial: Partial<StoreState>) {
    this.state = { ...this.state, ...partial };
    this.emit();
  }

  setSelectedPacket(p: PacketData | null) { this.patch({ selectedPacket: p }); }
  setActiveInterface(iface: string) { this.patch({ activeInterface: iface }); }
  setReplaySpeed(speed: number) { this.patch({ replaySpeed: speed }); }
  setBackendError(msg: string | null) { this.patch({ backendError: msg }); }

  unlockAchievement(id: string) {
    if (this.state.achievements.includes(id)) return;
    const next = [...this.state.achievements, id];
    localStorage.setItem('hexsniff_achievements', JSON.stringify(next));
    this.patch({ achievements: next });
  }

  private addPackets(pkts: PacketData[]) {
    if (!pkts.length) return;

    this.ppsAccum += pkts.length;
    
    const counts = { ...this.state.protocolCounts };
    let updatedAlerts = [...this.state.alerts];
    let alertsChanged = false;

    pkts.forEach(pkt => {
      this.bpsAccum += pkt.length;
      const proto = pkt.proto.toUpperCase();
      if (proto in counts) counts[proto]++;
      else counts['Other']++;

      if (pkt.alerts && pkt.alerts.length > 0) {
        pkt.alerts.forEach((incoming: Alert) => {
          alertsChanged = true;
          const key = `${incoming.category}-${incoming.src_ip}-${incoming.dst_ip}`;
          const existingIdx = updatedAlerts.findIndex(a => 
            `${a.category}-${a.src_ip}-${a.dst_ip}` === key
          );

          if (existingIdx >= 0) {
            const ext = updatedAlerts[existingIdx];
            const ev = (ext.evidence_packets || 1) + 1;
            
            // Re-calculate live confidence & threat score
            let base = 50;
            if (ext.severity === 'Critical') base = 80;
            if (ext.severity === 'High') base = 70;
            const conf = Math.min(100, base + (ev * 2));
            
            let tScore = 0;
            if (ext.severity === 'Critical') tScore += 40;
            else if (ext.severity === 'High') tScore += 30;
            else if (ext.severity === 'Medium') tScore += 15;
            else tScore += 5;
            
            if (ext.ioc_hit) {
              if (ext.severity === 'Critical') tScore += 30;
              else if (ext.severity === 'High') tScore += 20;
              else tScore += 10;
            }
            
            tScore += Math.min(20, ev * 2);
            tScore += Math.min(10, conf / 10);
            
            const tactic = ext.mitre_tactic || '';
            if (['Command and Control', 'Exfiltration', 'Impact'].includes(tactic)) tScore += 15;
            else if (['Initial Access', 'Credential Access', 'Lateral Movement'].includes(tactic)) tScore += 10;
            
            tScore = Math.floor(Math.min(100, Math.max(0, tScore)));
            let rLevel = 'LOW';
            if (tScore >= 80) rLevel = 'CRITICAL';
            else if (tScore >= 60) rLevel = 'HIGH';
            else if (tScore >= 30) rLevel = 'MEDIUM';
            
            updatedAlerts[existingIdx] = {
              ...ext,
              evidence_packets: ev,
              last_seen: pkt.timestamp,
              confidence: conf,
              timestamp: pkt.timestamp,
              threat_score: tScore,
              risk_level: rLevel
            };
            
            // Move to top of list
            const [moved] = updatedAlerts.splice(existingIdx, 1);
            updatedAlerts.unshift(moved);
          } else {
            let base = 50;
            if (incoming.severity === 'Critical') base = 80;
            if (incoming.severity === 'High') base = 70;

            let tScore = 0;
            if (incoming.severity === 'Critical') tScore += 40;
            else if (incoming.severity === 'High') tScore += 30;
            else if (incoming.severity === 'Medium') tScore += 15;
            else tScore += 5;
            
            if (incoming.ioc_hit) {
              if (incoming.severity === 'Critical') tScore += 30;
              else if (incoming.severity === 'High') tScore += 20;
              else tScore += 10;
            }
            
            tScore += 2; // evidence=1
            tScore += Math.min(10, base / 10);
            
            const tactic = incoming.mitre_tactic || '';
            if (['Command and Control', 'Exfiltration', 'Impact'].includes(tactic)) tScore += 15;
            else if (['Initial Access', 'Credential Access', 'Lateral Movement'].includes(tactic)) tScore += 10;
            
            tScore = Math.floor(Math.min(100, Math.max(0, tScore)));
            let rLevel = 'LOW';
            if (tScore >= 80) rLevel = 'CRITICAL';
            else if (tScore >= 60) rLevel = 'HIGH';
            else if (tScore >= 30) rLevel = 'MEDIUM';

            updatedAlerts.unshift({
              ...incoming,
              id: `${incoming.id}_${Date.now()}`,
              evidence_packets: 1,
              first_seen: pkt.timestamp,
              last_seen: pkt.timestamp,
              confidence: base,
              timestamp: pkt.timestamp,
              packetId: pkt.id,
              threat_score: tScore,
              risk_level: rLevel
            });
          }
        });
      }
    });

    const packets = [...this.state.packets, ...pkts];
    if (packets.length > MAX_PACKETS) packets.splice(0, packets.length - MAX_PACKETS);

    if (updatedAlerts.length > 200) {
      updatedAlerts = updatedAlerts.slice(0, 200);
    }

    const alerts = alertsChanged ? updatedAlerts : this.state.alerts;

    console.log("Packet Store Count:", packets.length);

    this.patch({
      packets,
      alerts,
      protocolCounts: counts,
      totalPackets: this.state.totalPackets + pkts.length,
    });

    if (alerts.length >= 1) this.unlockAchievement('first_alert');
    if (alerts.length >= 10) this.unlockAchievement('threat_hunter');
    if (this.state.totalPackets >= 100) this.unlockAchievement('packet_collector');
    if (counts['DNS'] >= 10) this.unlockAchievement('dns_expert');
  }

  private resetCapture() {
    this.patch({
      packets: [],
      alerts: [],
      totalPackets: 0,
      selectedPacket: null,
      protocolCounts: { TCP: 0, UDP: 0, DNS: 0, ICMP: 0, ARP: 0, Other: 0 },
      timelineLabels: Array(TIMELINE_LEN).fill(''),
      timelineCounts: Array(TIMELINE_LEN).fill(0),
    });
  }

  private startRateTracker() {
    this.ppsAccum = 0;
    this.bpsAccum = 0;
    if (this.rateInterval) clearInterval(this.rateInterval);
    this.rateInterval = window.setInterval(() => {
      const pps = this.ppsAccum;
      const kbps = this.bpsAccum / 1024;
      this.ppsAccum = 0;
      this.bpsAccum = 0;
      const now = new Date().toLocaleTimeString([], { hour12: false });
      const tl = [...this.state.timelineLabels.slice(1), now];
      const tc = [...this.state.timelineCounts.slice(1), pps];
      this.patch({ packetRate: pps, dataRate: kbps, timelineLabels: tl, timelineCounts: tc });
    }, 1000);
  }

  private stopRateTracker() {
    if (this.rateInterval) { clearInterval(this.rateInterval); this.rateInterval = null; }
    this.patch({ packetRate: 0, dataRate: 0 });
  }

  connectWS(pendingAction?: object) {
    if (this.socket) { 
      this.socket.onclose = null; // Prevent infinite reconnect loop
      try { this.socket.close(); } catch {/* */} 
    }
    this.patch({ backendError: null });
    const ws = new WebSocket('ws://127.0.0.1:8000/ws/packets');
    this.socket = ws;

    ws.onopen = () => {
      if (pendingAction) {
        ws.send(JSON.stringify(pendingAction));
      }
    };

    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === 'error') {
          console.error('[HexSniff WS] Backend error:', data.message);
          this.patch({ backendError: data.message });
          this.stop();
          return;
        }
        if (data.type === 'status') {
          if (data.mode === 'live') {
            this.patch({ mode: 'live', activeInterface: data.interface });
            this.startRateTracker();
            if (this.flushInterval) clearInterval(this.flushInterval);
            this.packetBuffer = [];
            this.flushInterval = window.setInterval(() => {
              if (this.packetBuffer.length > 0) {
                this.addPackets(this.packetBuffer);
                this.packetBuffer = [];
              }
            }, 100);
          } else if (data.mode === 'replay') {
            this.patch({ mode: 'replay' });
            this.startRateTracker();
            if (this.flushInterval) clearInterval(this.flushInterval);
            this.packetBuffer = [];
            this.flushInterval = window.setInterval(() => {
              if (this.packetBuffer.length > 0) {
                this.addPackets(this.packetBuffer);
                this.packetBuffer = [];
              }
            }, 100);
          }
          return;
        }
        if (data.type === 'info') {
          return;
        }
        console.log("WS Packet:", data.id);
        // Buffer packets to avoid React render thrashing
        this.packetBuffer.push(data as PacketData);

      } catch (e) {
        console.error('[HexSniff WS] Failed to parse message:', ev.data, e);
      }
    };

    ws.onerror = (ev) => {
      console.error('[HexSniff WS] WebSocket error:', ev);
      this.patch({ backendError: 'WebSocket connection lost.' });
    };

    ws.onclose = () => {
      // Reconnect automatically if we were expecting to be connected
      if (this.state.mode) {
        setTimeout(() => this.connectWS(), 2000);
      }
    };
  }

  startLive(iface: string) {
    this.resetCapture();
    this.connectWS({ action: 'start_live', interface: iface });
    this.startRateTracker();
    
    // Start flush interval (100ms = 10fps rendering)
    if (this.flushInterval) clearInterval(this.flushInterval);
    this.packetBuffer = [];
    this.flushInterval = window.setInterval(() => {
      if (this.packetBuffer.length > 0) {
        this.addPackets(this.packetBuffer);
        this.packetBuffer = [];
      }
    }, 100);

    this.patch({ mode: 'live', activeInterface: iface });
    this.unlockAchievement('first_capture');
  }

  startReplay() {
    this.resetCapture();
    this.connectWS({ action: 'start_replay', speed: this.getState().replaySpeed });
    this.startRateTracker();

    // Start flush interval
    if (this.flushInterval) clearInterval(this.flushInterval);
    this.packetBuffer = [];
    this.flushInterval = window.setInterval(() => {
      if (this.packetBuffer.length > 0) {
        this.addPackets(this.packetBuffer);
        this.packetBuffer = [];
      }
    }, 100);

    this.patch({ mode: 'replay' });
    this.unlockAchievement('simulator');
  }

  sendFilter(filterStr: string) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({ action: 'set_filter', filter: filterStr }));
    }
  }

  stop() {
    if (this.socket) {
      if (this.socket.readyState === WebSocket.OPEN)
        this.socket.send(JSON.stringify({ action: 'stop' }));
      this.socket.close();
      this.socket = null;
    }
    if (this.flushInterval) { clearInterval(this.flushInterval); this.flushInterval = null; }
    this.packetBuffer = [];
    this.stopRateTracker();
    this.patch({ mode: null });
  }

  loadPcap(result: { packets: PacketData[] }) {
    this.stop();
    const pkts = result.packets;
    const counts = { TCP: 0, UDP: 0, DNS: 0, ICMP: 0, ARP: 0, Other: 0 };
    const alerts: Alert[] = [];
    pkts.forEach(p => {
      const proto = p.proto.toUpperCase();
      if (proto in counts) (counts as Record<string, number>)[proto]++; else counts['Other']++;
      (p.alerts || []).forEach(a => alerts.push({ ...a, timestamp: p.timestamp, packetId: p.id }));
    });

    const sorted = [...pkts].sort((a, b) => a.timestamp - b.timestamp);
    const start = sorted[0]?.timestamp || 0;
    const duration = Math.max(1, (sorted[sorted.length - 1]?.timestamp || 0) - start);
    const bucketSz = Math.max(1, Math.ceil(duration / TIMELINE_LEN));
    const counts2: number[] = Array(Math.ceil(duration / bucketSz)).fill(0);
    sorted.forEach(p => { const idx = Math.floor((p.timestamp - start) / bucketSz); if (idx >= 0 && idx < counts2.length) counts2[idx]++; });

    this.patch({
      packets: pkts.slice(0, MAX_PACKETS),
      alerts: alerts.reverse().slice(0, 200),
      totalPackets: pkts.length,
      selectedPacket: pkts[0] || null,
      protocolCounts: counts,
      timelineLabels: counts2.map((_, i) => `+${i * bucketSz}s`),
      timelineCounts: counts2,
      mode: null,
    });
    this.unlockAchievement('pcap_analyst');
  }

  async fetchInterfaces() {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/interfaces');
      const data: NetworkInterface[] = await res.json();
      this.patch({ interfaces: data, activeInterface: data[0]?.name || '' });
    } catch {
      this.patch({ backendError: 'Cannot connect to backend at localhost:8000. Start the Python server.' });
    }
  }

  async fetchCoverageStats() {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/coverage/stats');
      if (res.ok) {
        const data: CoverageStats = await res.json();
        this.patch({ coverageStats: data });
      }
    } catch (e) {
      console.error('Failed to fetch coverage stats:', e);
    }
  }

  // --- Threat Hunting APIs ---
  async executeHunt(entity: string, params: Record<string, any>) {
    this.patch({ isHunting: true });
    try {
      const res = await fetch('http://127.0.0.1:8000/api/hunt/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entity, params })
      });
      if (res.ok) {
        const data = await res.json();
        this.patch({ huntResults: data.results });
        return data.results;
      }
    } catch (e) {
      console.error('Hunt failed:', e);
    } finally {
      this.patch({ isHunting: false });
    }
    return [];
  }

  async executeNLHunt(query: string) {
    this.patch({ isHunting: true });
    try {
      const res = await fetch('http://127.0.0.1:8000/api/hunt/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.success) {
            this.patch({ huntResults: data.results });
            return { results: data.results, interpreted: data.interpreted_query };
        }
      }
    } catch (e) {
      console.error('NL Hunt failed:', e);
    } finally {
      this.patch({ isHunting: false });
    }
    return null;
  }

  async fetchHuntGraph() {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/hunt/graph');
      if (res.ok) {
        const data = await res.json();
        this.patch({ huntGraph: data.graph });
        return data.graph;
      }
    } catch (e) {
      console.error('Failed to fetch hunt graph:', e);
    }
    return null;
  }

  async pivotHunt(source_type: string, source_id: string, target_type: string) {
    this.patch({ isHunting: true });
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/hunt/pivot?source_type=${source_type}&source_id=${source_id}&target_type=${target_type}`);
      if (res.ok) {
        const data = await res.json();
        this.patch({ huntResults: data.results });
        return data.results;
      }
    } catch (e) {
      console.error('Pivot failed:', e);
    } finally {
      this.patch({ isHunting: false });
    }
    return [];
  }
}

export const store = new PacketStore();

export function useStore(): StoreState {
  const [, forceUpdate] = useState(0);
  useEffect(() => {
    const unsub = store.subscribe(() => forceUpdate(n => n + 1));
    return () => { unsub(); };
  }, []);
  return store.getState();
}
