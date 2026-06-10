import { useState, useEffect, useRef } from 'react';
import {
  Play, Square, Activity, Upload, AlertCircle,
  Terminal, Database, Search, Filter, X, Shield, ShieldAlert, FileCode2
} from 'lucide-react';
import { useStore, store } from '../store';
import { m } from 'framer-motion';

// ── Control Panel ─────────────────────────────────────────────────────────────
function ControlPanel() {
  const { interfaces, mode, activeInterface, replaySpeed } = useStore();
  const fileRef = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadErr, setUploadErr] = useState<string | null>(null);

  const handleFile = async (file: File) => {
    if (!file.name.match(/\.pcap(ng)?$/i)) { setUploadErr('Only .pcap/.pcapng files'); return; }
    setUploading(true); setUploadErr(null);
    try {
      const fd = new FormData(); fd.append('file', file);
      const res = await fetch('http://127.0.0.1:8000/api/upload-pcap', { method: 'POST', body: fd });
      if (!res.ok) throw new Error((await res.json()).detail);
      store.loadPcap(await res.json());
    } catch (e) { setUploadErr(e instanceof Error ? e.message : String(e)); }
    finally { setUploading(false); }
  };

  return (
    <div className="glass-panel rounded-xl flex flex-col overflow-hidden h-full shadow-card">
      <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02] shrink-0">
        <Activity size={14} className="text-neon-blue" /> Capture Controls
      </div>
      <div className="p-5 flex flex-col gap-5 overflow-y-auto">
        
        {/* Interface selector */}
        <div>
          <div className="text-xs font-sans font-medium text-text-muted mb-2">Network Interface</div>
          <select
            className="w-full bg-black/20 border border-border-dim text-text-main text-xs font-sans rounded-lg p-3 outline-none focus:border-neon-blue focus:ring-1 focus:ring-neon-blue transition-all"
            value={activeInterface}
            onChange={e => store.setActiveInterface(e.target.value)}
            disabled={mode !== null}
          >
            {interfaces.map(i => (
              <option key={i.name} value={i.name}>{i.description}</option>
            ))}
          </select>
        </div>

        {/* Action buttons */}
        <div className="flex flex-col gap-2">
          {mode === null ? (
            <button 
              className="btn-cyber flex items-center justify-center gap-2 w-full bg-neon-blue/10 text-neon-blue border border-neon-blue/30 p-3 rounded-lg text-xs font-sans font-semibold disabled:opacity-50 disabled:cursor-not-allowed" 
              onClick={() => store.startLive(activeInterface)} 
              disabled={!activeInterface}
            >
              <Play size={14} /> Start Live Capture
            </button>
          ) : (
            <button 
              className="btn-cyber flex items-center justify-center gap-2 w-full bg-crimson/10 text-crimson border border-crimson/30 p-3 rounded-lg text-xs font-sans font-semibold" 
              onClick={() => store.stop()}
            >
              <Square size={14} /> Stop Capture
            </button>
          )}
        </div>

        <div className="h-px bg-border-dim w-full my-2" />

        {/* Replay Engine Controls */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs font-sans font-medium text-text-muted">PCAP Replay Engine</div>
            <select
              className="bg-black/20 border border-border-dim text-neon-blue text-[10px] font-mono rounded px-2 py-1 outline-none cursor-pointer"
              value={replaySpeed}
              onChange={(e) => store.setReplaySpeed(Number(e.target.value))}
              disabled={mode !== null}
            >
              <option value={1}>1x Speed</option>
              <option value={2}>2x Speed</option>
              <option value={5}>5x Speed</option>
              <option value={10}>10x Speed</option>
            </select>
          </div>
          <button 
            className="btn-cyber flex items-center justify-center gap-2 w-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 p-3 rounded-lg text-xs font-sans font-semibold disabled:opacity-50 disabled:cursor-not-allowed mb-3" 
            onClick={() => store.startReplay()} 
            disabled={mode !== null}
          >
            <Play size={14} /> Start WebSocket Replay
          </button>
        </div>

        {/* PCAP upload */}
        <div>
          <div className="text-xs font-sans font-medium text-text-muted mb-2">Offline Forensics</div>
          <div
            className={`flex flex-col items-center justify-center p-6 border-2 border-dashed rounded-xl cursor-pointer transition-all ${
              drag ? 'border-neon-blue bg-neon-blue/5' : 'border-border-dim hover:border-border-subtle bg-black/10 hover:bg-black/20'
            }`}
            onDragEnter={() => setDrag(true)}
            onDragLeave={() => setDrag(false)}
            onDragOver={e => e.preventDefault()}
            onDrop={e => { e.preventDefault(); setDrag(false); if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); }}
            onClick={() => fileRef.current?.click()}
          >
            <input ref={fileRef} type="file" accept=".pcap,.pcapng" className="hidden" onChange={e => { if (e.target.files?.[0]) handleFile(e.target.files[0]); }} />
            <Upload size={24} className={`mb-3 ${drag ? 'text-neon-blue' : 'text-text-muted'}`} />
            <div className="text-xs text-center text-text-main">
              {uploading ? 'Parsing PCAP...' : (
                <span className="font-mono">Drop .pcap or <span className="text-neon-blue underline">browse</span></span>
              )}
            </div>
          </div>
          {uploadErr && (
            <div className="mt-2 p-2 bg-crimson/10 border border-crimson/30 text-crimson text-[10px] rounded flex items-center gap-1.5">
              <AlertCircle size={12} className="shrink-0" />
              <span>{uploadErr}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Packet Table ──────────────────────────────────────────────────────────────
function PacketTable({ filter }: { filter: string }) {
  const { packets, selectedPacket } = useStore();
  const ref = useRef<HTMLDivElement>(null);

  const filtered = filter.trim()
    ? packets.filter(p => {
      const q = filter.toLowerCase();
      return (
        p.src_ip.includes(q) || p.dst_ip.includes(q) ||
        p.proto.toLowerCase().includes(q) ||
        String(p.src_port).includes(q) || String(p.dst_port).includes(q) ||
        (p.dns_query || '').toLowerCase().includes(q) ||
        p.summary.toLowerCase().includes(q) ||
        p.src_mac.toLowerCase().includes(q) || p.dst_mac.toLowerCase().includes(q)
      );
    })
    : packets;

  console.log("Matrix Props:", packets.length);
  console.log("Rendered Rows:", filtered.length);

  const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString();

  return (
    <div className="glass-panel rounded-xl flex flex-col overflow-hidden h-full shadow-card">
      <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02] shrink-0">
        <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
          <Terminal size={14} className="text-neon-blue" /> Live Data Matrix
        </div>
        <span className="text-[10px] font-mono text-neon-blue bg-neon-blue/10 px-2 py-0.5 rounded-full border border-neon-blue/20">
          {filtered.length.toLocaleString()} pkts
        </span>
      </div>
      
      <div className="flex-1 overflow-auto custom-scrollbar bg-void" ref={ref}>
        {filtered.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-text-muted opacity-50 p-8 text-center">
            <Terminal size={48} className="mb-4" />
            <p className="text-sm font-sans tracking-wide">Awaiting Data Stream</p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse text-[11px] font-mono whitespace-nowrap">
            <thead className="sticky top-0 bg-[#060c18] border-b border-border-dim z-10 shadow-md">
              <tr className="text-[10px] uppercase tracking-wider text-text-muted bg-white/[0.01]">
                <th className="py-3 px-5 font-medium">Time</th>
                <th className="py-3 px-5 font-medium">Proto</th>
                <th className="py-3 px-5 font-medium">Source</th>
                <th className="py-3 px-5 font-medium">Destination</th>
                <th className="py-3 px-5 font-medium">Len</th>
                <th className="py-3 px-5 font-medium">Info</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {filtered.map((pkt, _i) => {
                const alert = pkt.alerts?.length > 0;
                const sel = selectedPacket?.id === pkt.id;
                return (
                  <tr 
                    key={pkt.id} 
                    className={`cursor-pointer border-b border-border-dim/30 hover:bg-white/10 transition-colors ${
                      sel ? 'bg-neon-blue/10 border-l-2 border-l-neon-blue' : 
                      alert ? 'bg-crimson/5 border-l-2 border-l-crimson' : 
                      'border-l-2 border-l-transparent'
                    }`}
                    onClick={() => store.setSelectedPacket(pkt)}
                  >
                    <td className="py-1.5 px-4 text-text-muted">{fmt(pkt.timestamp)}</td>
                    <td className="py-1.5 px-4">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${pkt.proto === 'TCP' ? 'bg-neon-blue/10 text-neon-blue border border-neon-blue/20' : 'bg-white/10 text-text-main border border-white/20'}`}>
                        {pkt.proto}
                      </span>
                    </td>
                    <td className="py-1.5 px-4 text-text-main">{pkt.src_ip}{pkt.src_port ? <span className="text-text-muted">:{pkt.src_port}</span> : ''}</td>
                    <td className="py-1.5 px-4 text-text-main">{pkt.dst_ip}{pkt.dst_port ? <span className="text-text-muted">:{pkt.dst_port}</span> : ''}</td>
                    <td className="py-1.5 px-4 text-text-muted">{pkt.length}</td>
                    <td className={`py-1.5 px-4 truncate max-w-[300px] ${alert ? 'text-crimson font-bold text-glow-red' : 'text-text-main'}`}>
                      {pkt.summary}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── Packet Inspector ──────────────────────────────────────────────────────────
function Inspector() {
  const { selectedPacket: pkt } = useStore();
  const [tab, setTab] = useState<'headers' | 'hex' | 'ascii'>('headers');

  if (!pkt) return (
    <div className="glass-panel rounded-xl flex flex-col overflow-hidden h-full shadow-card">
      <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02] shrink-0">
        <Database size={14} className="text-neon-blue" /> Packet Inspector
      </div>
      <div className="h-full flex flex-col items-center justify-center text-text-muted opacity-50 p-8 text-center">
        <Database size={48} className="mb-4" />
        <p className="text-sm font-sans tracking-wide">Select packet to inspect</p>
      </div>
    </div>
  );

  return (
    <div className="glass-panel rounded-xl flex flex-col overflow-hidden h-full shadow-card">
      <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02] shrink-0">
        <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
          <Database size={14} className="text-neon-blue" /> FRAME {pkt.id.toUpperCase().slice(0, 8)}
        </div>
        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-white/10 border border-white/20">
          {pkt.proto}
        </span>
      </div>
      
      <div className="flex bg-black/20 border-b border-border-dim shrink-0">
        {(['headers', 'hex', 'ascii'] as const).map(t => (
          <button 
            key={t} 
            className={`flex-1 py-3 text-xs font-sans font-semibold tracking-wide transition-all ${
              tab === t ? 'text-neon-blue border-b-2 border-neon-blue bg-neon-blue/5' : 'text-text-muted hover:bg-white/5 hover:text-text-main border-b-2 border-transparent'
            }`} 
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto custom-scrollbar p-5 bg-void">
        {tab === 'headers' && (
          <div className="flex flex-col gap-3 font-mono text-[11px]">
            <div className="border border-border-dim rounded-md overflow-hidden bg-white/5">
              <div className="bg-black/40 px-3 py-1.5 font-bold text-text-main border-b border-border-dim">Frame Overview</div>
              <div className="p-3 grid grid-cols-[100px_1fr] gap-x-4 gap-y-2">
                <span className="text-text-muted">Length</span><span className="text-neon-blue">{pkt.length} bytes</span>
                <span className="text-text-muted">Src MAC</span><span className="text-text-main">{pkt.src_mac}</span>
                <span className="text-text-muted">Dst MAC</span><span className="text-text-main">{pkt.dst_mac}</span>
              </div>
            </div>

            {(pkt.proto !== 'ARP') && (
              <div className="border border-border-dim rounded-md overflow-hidden bg-white/5">
                <div className="bg-black/40 px-3 py-1.5 font-bold text-text-main border-b border-border-dim">Network Layer (IP)</div>
                <div className="p-3 grid grid-cols-[100px_1fr] gap-x-4 gap-y-2">
                  <span className="text-text-muted">Src IP</span><span className="text-neon-blue">{pkt.src_ip}</span>
                  <span className="text-text-muted">Dst IP</span><span className="text-neon-blue">{pkt.dst_ip}</span>
                  <span className="text-text-muted">Protocol</span><span className="text-text-main">{pkt.proto}</span>
                </div>
              </div>
            )}

            {(pkt.src_port || pkt.dst_port) && (
              <div className="border border-border-dim rounded-md overflow-hidden bg-white/5">
                <div className="bg-black/40 px-3 py-1.5 font-bold text-text-main border-b border-border-dim">Transport Layer</div>
                <div className="p-3 grid grid-cols-[100px_1fr] gap-x-4 gap-y-2">
                  <span className="text-text-muted">Src Port</span><span className="text-neon-blue">{pkt.src_port}</span>
                  <span className="text-text-muted">Dst Port</span><span className="text-neon-blue">{pkt.dst_port}</span>
                  {pkt.tcp_flags && <><span className="text-text-muted">Flags</span><span className="text-[#00FF66]">{pkt.tcp_flags}</span></>}
                </div>
              </div>
            )}

            {pkt.dns_query && (
              <div className="border border-border-dim rounded-md overflow-hidden bg-white/5">
                <div className="bg-black/40 px-3 py-1.5 font-bold text-text-main border-b border-border-dim">DNS Query</div>
                <div className="p-3 grid grid-cols-[100px_1fr] gap-x-4 gap-y-2">
                  <span className="text-text-muted">Domain</span><span className="text-[#00FF66]">{pkt.dns_query}</span>
                </div>
              </div>
            )}

            {pkt.alerts?.length > 0 && (
              <div className="border border-crimson/50 rounded-md overflow-hidden bg-crimson/5 shadow-[0_0_15px_rgba(255,0,60,0.1)]">
                <div className="bg-crimson/20 px-3 py-1.5 font-bold text-crimson border-b border-crimson/30 flex items-center gap-2 text-glow-red">
                  <ShieldAlert size={14} /> IDS Alerts ({pkt.alerts.length})
                </div>
                <div className="p-3 flex flex-col gap-3">
                  {pkt.alerts.map(a => (
                    <div key={a.id} className="flex flex-col gap-1.5 pb-2 border-b border-crimson/20 last:border-0 last:pb-0">
                      <span className="text-crimson font-bold text-[10px]">
                        [{a.severity.toUpperCase()}] {a.category}: {a.message}
                      </span>
                      <div className="flex flex-wrap gap-2">
                        {a.mitre_technique && (
                          <span className="text-[9px] bg-neon-blue/10 text-neon-blue px-1.5 py-0.5 rounded border border-neon-blue/20">
                            {a.mitre_technique}
                          </span>
                        )}
                        {a.mitre_tactic && (
                          <span className="text-[9px] bg-purple-500/10 text-purple-400 px-1.5 py-0.5 rounded border border-purple-500/20">
                            {a.mitre_tactic}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'hex' && (
          pkt.hex_dump ? (
            <div className="flex gap-4 font-mono text-[11px] leading-relaxed">
              <div className="text-text-muted whitespace-pre select-text selection:bg-neon-blue selection:text-void">{pkt.hex_dump}</div>
              <div className="text-[#00FF66] whitespace-pre select-text opacity-70 selection:bg-neon-blue selection:text-void">{pkt.ascii_dump}</div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-text-muted opacity-50">
              <FileCode2 size={32} className="mb-2" />
              <p>NO PAYLOAD DATA</p>
            </div>
          )
        )}

        {tab === 'ascii' && (
          pkt.ascii_dump ? (
            <pre className="font-mono text-[11px] text-[#00FF66] leading-relaxed whitespace-pre-wrap select-text selection:bg-neon-blue selection:text-void">
              {pkt.ascii_dump}
            </pre>
          ) : (
             <div className="h-full flex flex-col items-center justify-center text-text-muted opacity-50">
              <FileCode2 size={32} className="mb-2" />
              <p>NO PAYLOAD DATA</p>
            </div>
          )
        )}
      </div>
    </div>
  );
}

// ── Alerts Panel ──────────────────────────────────────────────────────────────
function AlertsPanel() {
  const { alerts, packets } = useStore();
  const fmt = (ts?: number) => ts ? new Date(ts * 1000).toLocaleTimeString() : '';

  return (
    <div className="glass-panel rounded-xl flex flex-col overflow-hidden h-full shadow-card">
      <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02] shrink-0">
        <div className={`flex items-center gap-2 text-xs font-sans font-semibold ${alerts.length > 0 ? 'text-crimson' : 'text-text-muted'}`}>
          <ShieldAlert size={14} className={alerts.length > 0 ? "animate-pulse" : ""} /> IDS Forensics Log
        </div>
        <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold border ${alerts.length > 0 ? 'bg-crimson/10 text-crimson border-crimson/30 shadow-glow-red' : 'bg-white/5 text-text-muted border-border-dim'}`}>
          {alerts.length} ALERTS
        </span>
      </div>
      
      <div className="flex-1 overflow-auto custom-scrollbar p-4 flex flex-col gap-3 bg-void">
        {alerts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-[#00FF66] opacity-70 p-4 text-center">
            <Shield size={32} className="mb-3" />
            <p className="text-xs font-bold tracking-widest uppercase shadow-[0_0_10px_rgba(0,255,102,0.5)]">No Threats Detected</p>
          </div>
        ) : alerts.map((a, i) => (
          <m.div 
            key={a.id} 
            initial={{ opacity: 0, x: 50, scale: 0.9, filter: "brightness(2)" }}
            animate={{ 
              opacity: 1, x: 0, scale: 1, filter: "brightness(1)",
              boxShadow: (a.severity === 'Critical' || a.severity === 'High') 
                ? ["0 0 0px rgba(255,42,85,0)", "0 0 20px rgba(255,42,85,0.6)", "0 0 0px rgba(255,42,85,0)"] 
                : "none"
            }}
            whileHover={{ scale: 1.02, x: -5, boxShadow: "0 0 30px rgba(255,42,85,0.4)" }}
            transition={{ 
              duration: 0.4, delay: i * 0.05, 
              boxShadow: { repeat: Infinity, duration: 2 } 
            }}
            className={`p-3 rounded-xl border-l-2 cursor-pointer transition-all ${
              a.severity === 'Critical' || a.severity === 'High' ? 'bg-crimson/5 border-crimson' : 
              a.severity === 'Medium' ? 'bg-orange-500/5 border-orange-500' : 
              'bg-neon-blue/5 border-neon-blue'
            }`}
            onClick={() => {
              const pkt = packets.find(p => p.id === a.packetId);
              if (pkt) store.setSelectedPacket(pkt);
            }}
          >
            <div className="flex justify-between items-start mb-1">
              <span className={`font-bold text-[11px] ${
                a.severity === 'Critical' || a.severity === 'High' ? 'text-crimson text-glow-red' : 
                a.severity === 'Medium' ? 'text-orange-400' : 'text-neon-blue'
              }`}>{a.category}</span>
              <span className="text-[9px] text-text-muted font-mono">{fmt(a.timestamp)}</span>
            </div>
            <div className="text-[10px] text-text-main mb-2 leading-relaxed">{a.message}</div>
            
            <div className="flex flex-wrap gap-2">
              {a.mitre_technique && (
                <span className="text-[9px] bg-white/5 text-text-muted px-1.5 py-0.5 rounded font-mono border border-white/10">
                  {a.mitre_technique}
                </span>
              )}
              {a.confidence !== undefined && (
                <span className="text-[9px] bg-white/5 text-text-muted px-1.5 py-0.5 rounded font-mono border border-white/10">
                  CONF: {a.confidence}%
                </span>
              )}
            </div>
          </m.div>
        ))}
      </div>
    </div>
  );
}

// ── Main Analyzer Page ────────────────────────────────────────────────────────
export function PacketAnalyzer() {
  const [filter, setFilter] = useState('');

  useEffect(() => {
    const handler = setTimeout(() => {
      store.sendFilter(filter);
    }, 300);
    return () => clearTimeout(handler);
  }, [filter]);

  return (
    <m.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="flex flex-col gap-4 h-full"
    >
      {/* Search bar */}
      <div className="flex gap-4 items-center shrink-0">
        <div className="flex-1 relative group">
          <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
            <Search size={16} className="text-neon-blue group-focus-within:text-glow-blue transition-colors" />
          </div>
          <input
            className="w-full bg-surface/50 backdrop-blur-xl border border-border-dim text-text-main text-sm font-mono rounded-xl pl-11 pr-8 py-3.5 outline-none focus:border-neon-blue focus:ring-1 focus:ring-neon-blue transition-all shadow-card"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter Expression: ip, proto, port, domain, mac, keyword..."
          />
          {filter && (
            <div className="absolute inset-y-0 right-0 pr-4 flex items-center">
              <X size={16} className="text-text-muted hover:text-text-main cursor-pointer" onClick={() => setFilter('')} />
            </div>
          )}
        </div>
        <div className="text-xs font-sans font-medium text-text-muted hidden md:flex items-center gap-2 shrink-0 bg-white/5 px-4 py-3.5 rounded-xl border border-white/10 shadow-card">
          <Filter size={14} className="text-neon-blue" /> Wireshark Syntax Active
        </div>
      </div>

      {/* Main layout */}
      <div className="flex flex-col lg:flex-row gap-4 flex-1 min-h-0">
        <div className="lg:w-[260px] shrink-0 h-full">
          <ControlPanel />
        </div>
        <div className="flex-1 flex flex-col gap-4 min-h-0">
          <div className="h-[40%] min-h-[200px]">
            <PacketTable filter={filter} />
          </div>
          <div className="flex flex-col md:flex-row gap-4 h-[60%] min-h-[300px]">
            <div className="flex-1 min-w-0">
              <Inspector />
            </div>
            <div className="flex-1 min-w-0">
              <AlertsPanel />
            </div>
          </div>
        </div>
      </div>
    </m.div>
  );
}
