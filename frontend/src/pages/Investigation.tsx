import { useState, useMemo, useEffect, useRef } from 'react';
import { Search, Clock, Network, Bookmark, FileText, Activity, ShieldAlert, Tag, ChevronRight, Hash, Database } from 'lucide-react';
import { useStore, store } from '../store';
import type { PacketData } from '../store';
import { m, AnimatePresence } from 'framer-motion';

interface AttackChain {
  chain_id: string;
  src_ip: string;
  start_time: number;
  last_update: number;
  tactics_progression: string; // JSON list
  alert_ids: string; // JSON list
  status: string;
}

interface Session {
  id: string;
  srcIp: string;
  dstIp: string;
  proto: string;
  packets: PacketData[];
  startTime: number;
  endTime: number;
  bytesTotal: number;
  alertCount: number;
}

function buildSessions(packets: PacketData[]): Session[] {
  const map = new Map<string, Session>();
  packets.forEach(p => {
    const key = `${p.src_ip}-${p.dst_ip}-${p.proto}`;
    if (!map.has(key)) {
      map.set(key, {
        id: key,
        srcIp: p.src_ip,
        dstIp: p.dst_ip,
        proto: p.proto,
        packets: [],
        startTime: p.timestamp,
        endTime: p.timestamp,
        bytesTotal: 0,
        alertCount: 0,
      });
    }
    const sess = map.get(key)!;
    sess.packets.push(p);
    sess.endTime = Math.max(sess.endTime, p.timestamp);
    sess.bytesTotal += p.length;
    sess.alertCount += (p.alerts || []).length;
  });
  return Array.from(map.values())
    .sort((a, b) => b.alertCount - a.alertCount || b.packets.length - a.packets.length)
    .slice(0, 20);
}

export function Investigation() {
  const { packets, selectedPacket } = useStore();
  const [selectedSession, setSelectedSession] = useState<Session | null>(null);
  const [bookmarks, setBookmarks] = useState<string[]>([]);
  const [filter, setFilter] = useState('');
  
  // Local Case Management State
  const [cases, setCases] = useState<Record<string, any>>({});
  const [isSaving, setIsSaving] = useState(false);
  const [timelineMode, setTimelineMode] = useState<'packets' | 'audit' | 'chains'>('packets');
  const [activeTab, setActiveTab] = useState<'sessions' | 'chains'>('sessions');
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const saveTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    fetch('http://127.0.0.1:8000/api/correlation/chains')
      .then(res => res.json())
      .then(data => setAttackChains(data))
      .catch(console.error);

    fetch('http://127.0.0.1:8000/api/cases')
      .then(res => res.json())
      .then((data: any[]) => {
        const map: Record<string, any> = {};
        data.forEach(c => map[c.case_id] = { status: c.status, severity: c.severity, tags: c.tags, notes: c.notes });
        setCases(map);
      })
      .catch(console.error);
  }, []);

  useEffect(() => {
    if (selectedSession) {
      const cid = selectedSession.id;
      if (!cases[cid]) {
        fetch('http://127.0.0.1:8000/api/cases', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ title: cid })
        })
        .then(res => res.json())
        .then(c => {
          setCases(prev => ({ ...prev, [c.case_id]: c }));
        }).catch(console.error);
      } else if (!cases[cid].timeline) {
        fetch(`http://127.0.0.1:8000/api/cases/${cid}`)
        .then(res => res.json())
        .then(c => {
          setCases(prev => ({ ...prev, [c.case_id]: c }));
        }).catch(console.error);
      }
    }
  }, [selectedSession]);

  const currentCase = selectedSession ? cases[selectedSession.id] || { status: 'Open', severity: 'Medium', tags: '', notes: '' } : null;

  const refreshCase = (cid: string) => {
    fetch(`http://127.0.0.1:8000/api/cases/${cid}`)
      .then(res => res.json())
      .then(c => setCases(prev => ({ ...prev, [c.case_id]: c })))
      .catch(console.error);
  };

  const attachEvidence = () => {
    if (!selectedSession || !selectedPacket) return;
    const cid = selectedSession.id;
    const isAlert = (selectedPacket.alerts || []).length > 0;
    const payload = {
      packet_id: selectedPacket.id,
      alert_id: isAlert ? selectedPacket.alerts![0].id : "",
      mitre_technique: isAlert ? selectedPacket.alerts![0].mitre_technique : "",
      mitre_tactic: isAlert ? selectedPacket.alerts![0].mitre_tactic : ""
    };
    
    fetch(`http://127.0.0.1:8000/api/cases/${cid}/evidence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    .then(() => refreshCase(cid))
    .catch(console.error);
  };

  const updateCase = (updates: Partial<{ status: string, severity: string, tags: string, notes: string }>) => {
    if (!selectedSession) return;
    const cid = selectedSession.id;
    setCases(prev => ({
      ...prev,
      [cid]: { ...(prev[cid] || { status: 'Open', severity: 'Medium', tags: '', notes: '' }), ...updates }
    }));
    
    setIsSaving(true);
    if (saveTimeout.current) clearTimeout(saveTimeout.current);
    saveTimeout.current = setTimeout(() => {
      fetch(`http://127.0.0.1:8000/api/cases/${cid}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates)
      })
      .finally(() => setIsSaving(false))
      .catch(console.error);
    }, 500);
  };

  const sessions = useMemo(() => buildSessions(packets), [packets]);
  const filteredSessions = filter.trim()
    ? sessions.filter(s => s.srcIp.includes(filter) || s.dstIp.includes(filter) || s.proto.toLowerCase().includes(filter.toLowerCase()))
    : sessions;

  const toggleBookmark = (id: string) => setBookmarks(b => b.includes(id) ? b.filter(x => x !== id) : [...b, id]);
  const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString();
  const dur = (s: Session) => `${(s.endTime - s.startTime).toFixed(1)}s`;

  return (
    <m.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5 }}
      className="flex flex-col gap-6 max-w-[1800px] mx-auto h-full pb-10"
    >
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display font-bold text-white tracking-wide mb-1">Investigation Workspace</h1>
          <p className="text-sm text-text-muted font-sans">Enterprise DFIR Evidence Explorer</p>
        </div>
        <div className="flex gap-4">
           <div className="glass-panel px-4 py-2 rounded-lg flex items-center gap-3">
             <Database size={16} className="text-neon-blue" />
             <span className="text-xs font-mono text-text-muted">Cases Active: <span className="text-white font-bold">{Object.keys(cases).length}</span></span>
           </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 flex-1 min-h-0">
        
        {/* ── Sessions List ── */}
        <div className="glass-panel rounded-2xl flex flex-col overflow-hidden h-full">
          <div className="px-5 py-4 border-b border-border-dim bg-surface-active/50 shrink-0">
            <div className="relative mb-2">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
              <input 
                value={filter} 
                onChange={e => setFilter(e.target.value)} 
                placeholder="Filter..." 
                className="w-full bg-void/50 border border-border-dim rounded-lg py-2 pl-9 pr-3 text-xs text-white font-mono focus:outline-none focus:border-neon-blue/50 transition-colors"
              />
            </div>
            <div className="flex bg-void/50 rounded-lg p-1">
              <button 
                onClick={() => setActiveTab('sessions')}
                className={`flex-1 text-[9px] font-bold uppercase tracking-widest py-1.5 rounded-md transition-colors ${activeTab === 'sessions' ? 'bg-surface-active text-white shadow-card' : 'text-text-muted hover:text-white'}`}
              >
                Raw Sessions
              </button>
              <button 
                onClick={() => setActiveTab('chains')}
                className={`flex-1 text-[9px] font-bold uppercase tracking-widest py-1.5 rounded-md transition-colors ${activeTab === 'chains' ? 'bg-crimson/20 text-crimson shadow-[inset_0_0_10px_rgba(255,0,0,0.2)]' : 'text-text-muted hover:text-white'}`}
              >
                Attack Chains
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar p-3 flex flex-col gap-2">
            {activeTab === 'sessions' ? filteredSessions.map(s => (
              <m.div 
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                key={s.id}
                onClick={() => setSelectedSession(s)}
                className={`p-4 rounded-xl cursor-pointer border transition-all flex flex-col gap-2 relative group
                  ${selectedSession?.id === s.id 
                    ? 'bg-neon-blue/10 border-neon-blue/30 shadow-[inset_0_0_20px_rgba(0,240,255,0.1)]' 
                    : 'bg-void/40 border-border-dim hover:border-border-bright hover:bg-surface-hover'}
                `}
              >
                <div className={`absolute left-0 top-0 bottom-0 w-1 rounded-l-xl ${s.alertCount > 0 ? 'bg-crimson shadow-glow-red' : 'bg-transparent group-hover:bg-neon-blue/50'}`} />

                <div className="flex justify-between items-center pl-2">
                  <span className={`px-2 py-0.5 rounded text-[9px] font-bold tracking-widest border uppercase
                    ${s.proto === 'TCP' ? 'bg-blue-500/10 text-blue-400 border-blue-500/30' : 
                      s.proto === 'UDP' ? 'bg-green-500/10 text-green-400 border-green-500/30' : 
                      'bg-purple-500/10 text-purple-400 border-purple-500/30'}`}
                  >
                    {s.proto}
                  </span>
                  {s.alertCount > 0 && <span className="px-2 py-0.5 rounded bg-crimson/10 text-crimson border border-crimson/30 text-[9px] font-bold tracking-widest animate-pulse">ALERTS</span>}
                </div>
                
                <div className="font-mono text-xs text-white pl-2">
                  <div className="truncate text-text-muted mb-1 flex items-center gap-2"><ChevronRight size={10} className="text-neon-blue" /> {s.srcIp}</div>
                  <div className="truncate text-text-muted flex items-center gap-2"><ChevronRight size={10} className="text-crimson" /> {s.dstIp}</div>
                </div>
                
                <div className="flex justify-between text-[9px] uppercase tracking-widest text-text-muted font-sans pl-2 pt-2 border-t border-border-dim mt-1">
                  <span>{s.packets.length} Pkts</span>
                  <span>{dur(s)}</span>
                </div>
              </m.div>
            )) : attackChains.filter(c => c.src_ip.includes(filter)).map(chain => {
                const tactics = JSON.parse(chain.tactics_progression || '[]');
                const alerts = JSON.parse(chain.alert_ids || '[]');
                return (
                  <m.div 
                    whileHover={{ scale: 1.02 }}
                    key={chain.chain_id}
                    onClick={() => setSelectedSession({
                      id: chain.chain_id,
                      srcIp: chain.src_ip,
                      dstIp: "Multiple Targets",
                      proto: "CORRELATED",
                      packets: [],
                      startTime: chain.start_time,
                      endTime: chain.last_update,
                      bytesTotal: 0,
                      alertCount: alerts.length
                    })}
                    className="p-4 rounded-xl cursor-pointer border border-crimson/30 bg-crimson/5 flex flex-col gap-2 relative group"
                  >
                    <div className="absolute left-0 top-0 bottom-0 w-1 rounded-l-xl bg-crimson shadow-glow-red" />
                    <div className="flex justify-between items-center pl-2">
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold tracking-widest border bg-crimson/20 text-crimson border-crimson/50 uppercase">
                        {chain.status} CHAIN
                      </span>
                    </div>
                    <div className="font-mono text-xs text-white pl-2 mt-1">
                      <div className="text-crimson mb-1 flex items-center gap-2"><ShieldAlert size={12} /> {chain.src_ip}</div>
                      <div className="text-[10px] text-text-muted">Targeting Multiple Hosts</div>
                    </div>
                    <div className="flex flex-wrap gap-1 pl-2 mt-1">
                      {tactics.map((t: string) => (
                        <span key={t} className="px-1.5 py-0.5 bg-orange-500/10 border border-orange-500/30 text-orange-400 rounded text-[8px] uppercase">{t}</span>
                      ))}
                    </div>
                    <div className="flex justify-between text-[9px] uppercase tracking-widest text-text-muted font-sans pl-2 pt-2 border-t border-border-dim/50 mt-1">
                      <span>{alerts.length} Correlated Alerts</span>
                      <span>{Math.floor(chain.last_update - chain.start_time)}s Dur</span>
                    </div>
                  </m.div>
                );
            })}
          </div>
        </div>

        {/* ── Main Investigation Area ── */}
        <div className="lg:col-span-3 flex flex-col gap-6 h-full">
          {!selectedSession ? (
            <div className="glass-panel rounded-2xl flex-1 flex flex-col items-center justify-center p-10 text-center border-dashed border-2 border-white/5 bg-[url('/grid.svg')] bg-center">
              <Network size={64} className="mb-6 opacity-20 text-neon-blue drop-shadow-[0_0_15px_rgba(0,240,255,0.5)]" />
              <p className="text-2xl font-display text-white font-bold mb-2 tracking-wide">Target Session Isolation</p>
              <p className="text-sm max-w-md text-text-muted">Engage a session from the lateral registry to extract payload hex-dumps, correlate MITRE techniques, and establish a case timeline.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-full min-h-0">
              
              {/* Timeline Flow */}
              <div className="glass-panel rounded-2xl flex flex-col overflow-hidden h-full relative">
                <div className="px-5 py-4 border-b border-border-dim bg-surface-active/50 shrink-0 flex justify-between items-center z-10">
                  <div className="flex items-center gap-4 text-xs font-sans font-bold text-white uppercase tracking-widest">
                    <Clock size={16} className="text-neon-blue" />
                    <button 
                      onClick={() => setTimelineMode('packets')}
                      className={`pb-1 border-b-2 ${timelineMode === 'packets' ? 'border-neon-blue text-white shadow-glow-blue' : 'border-transparent text-text-muted'}`}
                    >
                      Incident Flow
                    </button>
                    <button 
                      onClick={() => setTimelineMode('audit')}
                      className={`pb-1 border-b-2 ${timelineMode === 'audit' ? 'border-neon-blue text-white shadow-glow-blue' : 'border-transparent text-text-muted'}`}
                    >
                      Case Audit
                    </button>
                  </div>
                </div>
                
                <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4 custom-scrollbar bg-void/30 relative">
                  {/* Vertical Timeline Rule */}
                  <div className="absolute left-10 top-0 bottom-0 w-px bg-border-dim" />

                  <AnimatePresence>
                    {timelineMode === 'packets' ? selectedSession.packets.map((p) => {
                      const isAlert = (p.alerts || []).length > 0;
                      return (
                        <m.div 
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          key={p.id} 
                          className={`relative flex gap-6 items-start group cursor-pointer`}
                          onClick={() => store.setSelectedPacket(p)}
                        >
                          <div className={`w-8 h-8 rounded-full border-2 bg-void flex items-center justify-center shrink-0 z-10 transition-colors
                            ${selectedPacket?.id === p.id ? 'border-neon-blue shadow-glow-blue' : isAlert ? 'border-crimson shadow-glow-red' : 'border-border-subtle group-hover:border-white'}
                          `}>
                            {isAlert ? <ShieldAlert size={12} className="text-crimson" /> : <Hash size={12} className="text-text-muted" />}
                          </div>
                          
                          <div className={`flex-1 glass-panel p-4 rounded-xl transition-all
                            ${selectedPacket?.id === p.id ? 'bg-surface-active border-neon-blue/50' : 'hover:bg-surface-hover'}
                          `}>
                            <div className="flex justify-between items-center mb-2">
                              <span className="text-mono text-[10px] text-text-muted font-mono bg-black/50 px-2 py-1 rounded">{fmt(p.timestamp)}</span>
                              {isAlert && <span className="text-[9px] uppercase tracking-widest text-crimson font-bold">Threat Detected</span>}
                            </div>
                            <p className={`text-sm ${isAlert ? 'text-crimson font-bold' : 'text-white'}`}>
                              {isAlert ? p.alerts![0].message : p.summary}
                            </p>
                          </div>
                        </m.div>
                      );
                    }) : currentCase?.timeline?.map((t: any) => (
                        <m.div 
                          initial={{ opacity: 0, scale: 0.95 }}
                          animate={{ opacity: 1, scale: 1 }}
                          key={t.event_id} 
                          className="relative flex gap-6 items-start"
                        >
                          <div className="w-8 h-8 rounded-full border-2 border-amber bg-void flex items-center justify-center shrink-0 z-10 shadow-glow-amber">
                            <Activity size={12} className="text-amber" />
                          </div>
                          <div className="flex-1 glass-panel p-4 rounded-xl border-amber/20 bg-amber/5">
                            <div className="text-mono text-[10px] text-amber font-mono mb-1">{fmt(t.timestamp)}</div>
                            <div className="text-[10px] text-white uppercase tracking-widest font-bold mb-1">{t.event_type}</div>
                            <div className="text-sm text-text-muted">{t.description}</div>
                          </div>
                        </m.div>
                    ))}
                  </AnimatePresence>
                </div>
              </div>

              {/* Investigation Context & Evidence */}
              <div className="flex flex-col gap-6 h-full min-h-0">
                {/* Case Management Pane */}
                <div className="glass-panel rounded-2xl flex flex-col shrink-0 p-6 gap-4 relative overflow-hidden">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-neon-blue/5 blur-[50px] pointer-events-none" />
                  
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-bold text-white uppercase tracking-widest flex items-center gap-2"><ShieldAlert size={16} className="text-neon-blue"/> Case Parameters</div>
                    <button onClick={() => toggleBookmark(selectedSession.id)}>
                       <Bookmark size={18} className={bookmarks.includes(selectedSession.id) ? "text-amber fill-amber drop-shadow-[0_0_10px_rgba(255,179,0,0.8)]" : "text-text-muted"} />
                    </button>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="flex flex-col gap-1">
                      <label className="text-[9px] uppercase tracking-widest text-text-muted font-bold">Status</label>
                      <select className="w-full bg-void/80 border border-border-dim rounded p-2 text-xs text-white outline-none focus:border-neon-blue" value={currentCase?.status} onChange={e => updateCase({ status: e.target.value })}>
                        <option>Open</option>
                        <option>Investigating</option>
                        <option>Closed</option>
                      </select>
                    </div>
                    <div className="flex flex-col gap-1">
                      <label className="text-[9px] uppercase tracking-widest text-text-muted font-bold">Severity</label>
                      <select className="w-full bg-void/80 border border-border-dim rounded p-2 text-xs text-white outline-none focus:border-neon-blue" value={currentCase?.severity} onChange={e => updateCase({ severity: e.target.value })}>
                        <option>Low</option>
                        <option>Medium</option>
                        <option>High</option>
                        <option>Critical</option>
                      </select>
                    </div>
                  </div>
                  <div className="flex flex-col gap-1">
                    <label className="text-[9px] uppercase tracking-widest text-text-muted font-bold flex items-center gap-1"><Tag size={10}/> Tags</label>
                    <input className="w-full bg-void/80 border border-border-dim rounded p-2 text-xs text-white font-mono focus:border-neon-blue outline-none" placeholder="e.g. Malware, Phishing" value={currentCase?.tags} onChange={e => updateCase({ tags: e.target.value })}/>
                  </div>
                </div>

                {/* Evidence Explorer */}
                <div className="glass-panel rounded-2xl flex flex-col flex-1 min-h-0">
                  <div className="px-5 py-4 border-b border-border-dim bg-surface-active/50 flex justify-between items-center">
                    <div className="flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest">
                      <FileText size={16} className="text-neon-blue" /> Evidence Explorer
                    </div>
                    <button 
                      disabled={!selectedPacket}
                      onClick={attachEvidence}
                      className="px-4 py-1.5 bg-neon-blue/10 border border-neon-blue/30 text-neon-blue rounded text-[10px] font-bold uppercase tracking-widest hover:bg-neon-blue/20 hover:shadow-glow-blue disabled:opacity-30 transition-all"
                    >
                      Attach
                    </button>
                  </div>
                  
                  <div className="flex-1 overflow-y-auto p-5 custom-scrollbar bg-void/50">
                    {selectedPacket ? (
                      <m.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-6">
                        {selectedPacket?.alerts?.[0] && (
                          <div className="p-4 bg-crimson/10 border border-crimson/30 rounded-xl text-xs text-crimson flex flex-col gap-2">
                            <strong className="tracking-widest uppercase">Detection Match</strong>
                            <span className="text-white font-mono">{selectedPacket.alerts[0].message}</span>
                            <div className="mt-2 text-[10px] text-crimson font-mono flex gap-4">
                              <span>Technique: {selectedPacket.alerts[0].mitre_technique}</span>
                              <span>Tactic: {selectedPacket.alerts[0].mitre_tactic}</span>
                            </div>
                          </div>
                        )}
                        <div>
                          <div className="text-[10px] text-text-muted mb-2 font-bold tracking-widest uppercase border-b border-border-dim pb-1">Payload Decoded</div>
                          <pre className="bg-void p-4 rounded-xl border border-border-dim text-xs text-emerald font-mono overflow-x-auto whitespace-pre-wrap break-all shadow-inner">
                            {selectedPacket?.ascii_dump || "NO ASCII PAYLOAD"}
                          </pre>
                        </div>
                        <div>
                          <div className="text-[10px] text-text-muted mb-2 font-bold tracking-widest uppercase border-b border-border-dim pb-1">Hex Stream</div>
                          <pre className="bg-void p-4 rounded-xl border border-border-dim text-[10px] text-text-dark font-mono overflow-x-auto shadow-inner">
                            {selectedPacket?.hex_dump || "NO HEX DATA"}
                          </pre>
                        </div>
                      </m.div>
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center text-text-muted/30">
                        <FileText size={48} className="mb-4" />
                        <span className="text-xs font-bold uppercase tracking-widest">Select packet to view evidence</span>
                      </div>
                    )}
                  </div>
                  
                  {/* Notes Area */}
                  <div className="h-32 border-t border-border-dim bg-void/80 p-0 relative">
                    <textarea
                      value={currentCase?.notes}
                      onChange={e => updateCase({ notes: e.target.value })}
                      placeholder="Case scratchpad... (auto-saves)"
                      className="w-full h-full bg-transparent border-none text-xs text-text-main p-5 resize-none focus:outline-none custom-scrollbar font-mono leading-relaxed"
                    />
                    {isSaving && <div className="absolute bottom-2 right-2 text-[9px] text-neon-blue uppercase tracking-widest animate-pulse">Saving...</div>}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

      </div>
    </m.div>
  );
}
