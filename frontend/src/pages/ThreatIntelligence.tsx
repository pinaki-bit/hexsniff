import { useState, useEffect, useMemo, useRef } from 'react';
import { Shield, AlertTriangle, CheckCircle, RefreshCw, Target, Clock, Zap, Upload, Download } from 'lucide-react';
import { useStore } from '../store';
import type { Alert } from '../store';
import { m, AnimatePresence } from 'framer-motion';
import { triggerDownload } from '../utils/download';

interface IOC {
  id: string;
  value: string;
  type: 'IP' | 'Domain' | 'URL' | 'Hash' | 'CVE';
  severity: 'critical' | 'high' | 'medium' | 'Critical' | 'High' | 'Medium';
  source: string;
  description: string;
  mitre: string;
  tags: string[];
  first_seen?: number;
  last_seen?: number;
  confidence?: number;
  active?: boolean;
  hit_count?: number;
}

const MITRE_PHASES = [
  { phase: 'Reconnaissance', count: 0, key: 'recon' },
  { phase: 'Initial Access', count: 0, key: 'initial' },
  { phase: 'Execution', count: 0, key: 'exec' },
  { phase: 'Persistence', count: 0, key: 'persist' },
  { phase: 'Priv. Escalation', count: 0, key: 'privesc' },
  { phase: 'Lateral Movement', count: 0, key: 'lateral' },
  { phase: 'Collection', count: 0, key: 'collection' },
  { phase: 'Exfiltration', count: 0, key: 'exfil' },
];

export function ThreatIntelligence() {
  const { alerts } = useStore();
  const [selectedIoc, setSelectedIoc] = useState<IOC | null>(null);
  const [, setSelectedAlert] = useState<Alert | null>(null);
  const [filterType, setFilterType] = useState<string>('All');
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [, setSyncResult] = useState<{ count: number; synced_at: number; errors: string[] } | null>(null);
  const [, setSyncError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchIocs = async () => {
    setLoading(true);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/iocs');
      if (res.ok) {
        const data = await res.json();
        setIocs(data);
      }
    } catch (e) {
      console.error('Failed to load IOC list:', e);
    } finally {
      setLoading(false);
    }
  };

  const syncFeeds = async () => {
    setSyncing(true);
    setSyncError(null);
    setSyncResult(null);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/iocs/sync', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        setSyncResult(data);
        await fetchIocs();
      } else {
        setSyncError(data.errors?.join('; ') || 'Sync failed');
      }
    } catch (e) {
      setSyncError(`Network error: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSyncing(false);
    }
  };

  const handleExport = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/iocs/export');
      if (res.ok) {
        const data = await res.json();
        triggerDownload(`threat-intel-export-${Date.now()}.json`, JSON.stringify(data, null, 2));
      }
    } catch (e) {
      console.error('Export failed:', e);
    }
  };

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    setSyncing(true);
    setSyncError(null);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/iocs/import', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (data.success) {
        setSyncResult({ count: data.imported_count, synced_at: Date.now() / 1000, errors: [] });
        await fetchIocs();
      } else {
        setSyncError(data.detail || 'Import failed');
      }
    } catch (err) {
      setSyncError(`Import error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSyncing(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  useEffect(() => { const timer = setTimeout(() => fetchIocs(), 0); return () => clearTimeout(timer); }, []);

  // Compute Kill Chain from alerts
  const killChain = useMemo(() => {
    return MITRE_PHASES.map((p, i) => {
      let count = 0;
      if (i === 0) count = alerts.filter(a => a.mitre_tactic === 'Reconnaissance' || a.mitre_tactic === 'Discovery').length;
      else if (i === 1) count = alerts.filter(a => a.mitre_tactic === 'Initial Access').length;
      else if (i === 2) count = alerts.filter(a => a.mitre_tactic === 'Command and Control').length;
      else if (i === 3) count = alerts.filter(a => a.mitre_tactic === 'Persistence').length;
      else if (i === 4) count = alerts.filter(a => a.mitre_tactic === 'Credential Access' || a.mitre_tactic === 'Privilege Escalation').length;
      else if (i === 5) count = alerts.filter(a => a.mitre_tactic === 'Lateral Movement').length;
      else if (i === 6) count = alerts.filter(a => a.mitre_tactic === 'Collection').length;
      else if (i === 7) count = alerts.filter(a => a.mitre_tactic === 'Exfiltration' || a.mitre_tactic === 'Impact').length;
      return { ...p, count };
    });
  }, [alerts]);

  const iocHits = useMemo(() => alerts.filter(a => a.ioc_hit), [alerts]);
  const filtered = filterType === 'All' ? iocs : iocs.filter(i => i.type === filterType);

  return (
    <m.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col gap-6 h-full max-w-[1600px] mx-auto pb-6"
    >

      {/* IOC Dashboard Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
        {[
          { label: 'Active Threat Signatures', val: iocs.length, icon: Shield, color: 'text-neon-blue' },
          { label: 'Correlated IOC Hits', val: iocHits.length, icon: Target, color: iocHits.length > 0 ? 'text-crimson text-glow-red' : 'text-[#00FF66]' },
          { label: 'High/Critical Threats', val: alerts.filter(a => a.risk_level === 'CRITICAL' || a.risk_level === 'HIGH').length, icon: AlertTriangle, color: 'text-crimson text-glow-red' },
          { label: 'Mitre Chain Hooks', val: killChain.filter(p => p.count > 0).length, icon: Zap, color: 'text-orange-400' },
        ].map((kpi, i) => (
          <m.div
            key={kpi.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="glass-panel p-4 rounded-xl flex items-center gap-4 group"
          >
            <div className={`w-10 h-10 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center shrink-0 transition-colors group-hover:bg-white/10 ${kpi.color}`}>
              <kpi.icon size={18} />
            </div>
            <div>
              <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted mb-1">{kpi.label}</div>
              <div className={`text-xl font-display font-bold ${kpi.color}`}>{kpi.val.toLocaleString()}</div>
            </div>
          </m.div>
        ))}
      </div>

      {/* MITRE Correlation */}
      <div className="glass-panel rounded-xl flex flex-col shrink-0 overflow-hidden">
        <div className="px-5 py-3 border-b border-border-dim flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-text-muted bg-black/20">
          <AlertTriangle size={14} className="text-orange-400" /> Cyber Kill Chain Mapping (MITRE ATT&CK)
        </div>
        <div className="p-5 overflow-x-auto custom-scrollbar">
          <div className="flex justify-between items-stretch min-w-[800px] gap-2">
            {killChain.map((phase, i) => (
              <m.div
                key={phase.key}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                whileHover={{ scale: 1.05, y: -5 }}
                className={`flex-1 flex flex-col items-center justify-center p-3 rounded-xl border transition-colors cursor-default ${phase.count > 0 ? 'bg-crimson/10 border-crimson shadow-glow-red text-crimson' : 'bg-black/20 border-border-dim text-text-muted opacity-60 hover:bg-white/5 hover:opacity-100 hover:border-white/20'}`}
              >
                <div className="text-[10px] font-mono font-bold mb-1 opacity-50">PHASE {String(i + 1).padStart(2, '0')}</div>
                <div className="text-[11px] font-bold text-center mb-2 h-8 flex items-center justify-center leading-tight">{phase.phase}</div>
                <div className={`text-xl font-display font-black ${phase.count > 0 ? 'text-crimson' : 'text-text-muted'}`}>{phase.count}</div>
              </m.div>
            ))}
          </div>
        </div>
      </div>

      {/* Investigation Split Layout */}
      <div className="flex flex-col lg:flex-row gap-6 flex-1 min-h-0">

        {/* IOC Timeline / Directory */}
        <div className="glass-panel rounded-xl lg:w-1/2 flex flex-col overflow-hidden">
          <div className="px-4 py-3 border-b border-border-dim flex flex-wrap justify-between items-center bg-black/20 gap-4">
            <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-text-muted">
              <Clock size={14} className="text-neon-blue" /> Threat Intelligence Directory
            </div>
            <div className="flex items-center gap-2">
              {['All', 'IP', 'Domain', 'URL', 'Hash'].map(t => (
                <button
                  key={t}
                  className={`text-[9px] font-bold uppercase px-2 py-1 rounded transition-colors ${filterType === t ? 'bg-neon-blue text-void' : 'bg-white/5 text-text-muted hover:bg-white/10 hover:text-text-main'}`}
                  onClick={() => setFilterType(t)}
                >
                  {t}
                </button>
              ))}
              <div className="w-px h-4 bg-border-dim mx-1" />
              <button className="flex items-center gap-1.5 text-[9px] font-bold uppercase px-2 py-1 rounded bg-white/5 text-text-main hover:bg-white/10 transition-colors" onClick={() => fileInputRef.current?.click()} disabled={syncing}>
                <Upload size={10} /> IMPORT
              </button>
              <input type="file" accept=".json" className="hidden" ref={fileInputRef} onChange={handleImport} />
              <button className="flex items-center gap-1.5 text-[9px] font-bold uppercase px-2 py-1 rounded bg-white/5 text-text-main hover:bg-white/10 transition-colors" onClick={handleExport}>
                <Download size={10} /> EXPORT
              </button>
              <div className="w-px h-4 bg-border-dim mx-1" />
              <button className="flex items-center gap-1.5 text-[9px] font-bold uppercase px-2 py-1 rounded bg-white/5 text-text-main hover:bg-white/10 transition-colors" onClick={syncFeeds} disabled={syncing}>
                <RefreshCw size={10} className={syncing ? "animate-spin" : ""} /> {syncing ? 'SYNCING...' : 'SYNC FEEDS'}
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar bg-[#020408]">
            {filtered.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-text-muted opacity-50 p-8 text-center">
                <Shield size={48} className="mb-4" />
                <p className="text-sm font-mono tracking-wide">NO INDICATORS LOADED</p>
                <p className="text-[10px] mt-2">Click "Sync Feeds" to fetch live threat data</p>
              </div>
            ) : (
              <table className="w-full text-left border-collapse text-[11px]">
                <thead className="sticky top-0 bg-[#060c18] border-b border-border-dim z-10 shadow-md">
                  <tr className="text-[9px] uppercase tracking-widest text-text-muted">
                    <th className="py-2.5 px-4 font-bold">Severity</th>
                    <th className="py-2.5 px-4 font-bold">Type</th>
                    <th className="py-2.5 px-4 font-bold">Indicator</th>
                    <th className="py-2.5 px-4 font-bold">Source</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  <AnimatePresence>
                    {filtered.map((ioc, i) => {
                      const sevLower = (ioc.severity || 'medium').toLowerCase();
                      return (
                        <m.tr
                          key={`${ioc.id}-${i}`}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0 }}
                          transition={{ delay: i * 0.02 }}
                          whileHover={{ scale: 1.02, backgroundColor: "rgba(255,255,255,0.1)", zIndex: 10, x: 5 }}
                          className={`cursor-pointer transition-colors border-b border-border-dim/30 ${selectedIoc?.id === ioc.id ? 'bg-neon-blue/10 border-l-2 border-l-neon-blue' : 'border-l-2 border-l-transparent'}`}
                          onClick={() => { setSelectedIoc(ioc); setSelectedAlert(null); }}
                        >
                          <td className="py-2.5 px-4">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${sevLower === 'critical' ? 'bg-crimson/20 text-crimson border border-crimson/30' :
                                sevLower === 'high' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                                  'bg-neon-blue/20 text-neon-blue border border-neon-blue/30'
                              }`}>
                              {ioc.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-4">
                            <span className="px-1.5 py-0.5 rounded text-[9px] bg-white/5 text-text-muted border border-white/10">{ioc.type}</span>
                          </td>
                          <td className="py-2.5 px-4 text-text-main">{ioc.value}</td>
                          <td className="py-2.5 px-4 text-text-muted truncate max-w-[120px]">{ioc.source}</td>
                        </m.tr>
                      );
                    })}
                  </AnimatePresence>
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Investigation Panel */}
        <div className="glass-panel rounded-xl lg:w-1/2 flex flex-col overflow-hidden">
          <div className="px-4 py-3 border-b border-border-dim flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-text-muted bg-black/20 shrink-0">
            <Target size={14} className="text-neon-blue" /> Investigation Target
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar p-6 bg-[#020408]">
            <AnimatePresence mode="wait">
              {selectedIoc ? (
                <m.div
                  key="ioc-details"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="flex flex-col gap-6"
                >
                  {/* Header */}
                  <div className="flex items-start justify-between border-b border-border-dim pb-6">
                    <div>
                      <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest mb-1">Indicator Value</div>
                      <div className="text-xl font-mono text-text-main font-bold break-all">{selectedIoc.value}</div>
                    </div>
                    <div className="flex gap-2 shrink-0">
                      <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest border ${selectedIoc.severity.toLowerCase() === 'critical' ? 'bg-crimson/20 text-crimson border-crimson/30 shadow-glow-red' :
                          selectedIoc.severity.toLowerCase() === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                            'bg-neon-blue/20 text-neon-blue border-neon-blue/30'
                        }`}>
                        {selectedIoc.severity} RISK
                      </span>
                      <span className="px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest bg-white/5 text-text-muted border border-white/10">{selectedIoc.type}</span>
                    </div>
                  </div>

                  {/* Details Grid */}
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest mb-1">Origin Feed Source</div>
                      <div className="text-xs font-mono text-neon-blue">{selectedIoc.source}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest mb-1">Database Stats</div>
                      <div className="text-xs font-mono text-text-main">
                        <div>Hits: <span className="text-neon-blue">{selectedIoc.hit_count || 0}</span></div>
                        <div>Confidence: <span className="text-neon-blue">{selectedIoc.confidence || 0}%</span></div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest mb-2">Threat Description</div>
                    <div className="text-sm text-text-main leading-relaxed bg-black/40 p-4 rounded-lg border border-border-dim">
                      {selectedIoc.description}
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] text-text-muted font-bold uppercase tracking-widest mb-2">MITRE ATT&CK Classification</div>
                    <div className="inline-flex items-center gap-2 bg-purple-500/10 border border-purple-500/20 px-3 py-1.5 rounded-lg text-xs font-mono text-purple-400">
                      <Zap size={14} /> {selectedIoc.mitre}
                    </div>
                  </div>

                  <div className="mt-4 flex items-center justify-center gap-2 px-4 py-3 bg-[#00FF66]/5 border border-[#00FF66]/20 rounded-lg text-[#00FF66] text-xs font-bold uppercase tracking-widest shadow-[0_0_15px_rgba(0,255,102,0.1)]">
                    <CheckCircle size={16} /> Signature Active in Detection Engine
                  </div>

                </m.div>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-text-muted opacity-50 p-8 text-center min-h-[400px]">
                  <Target size={48} className="mb-4" />
                  <p className="text-sm font-mono tracking-wide">SELECT INDICATOR TO INVESTIGATE</p>
                </div>
              )}
            </AnimatePresence>
          </div>
        </div>

      </div>

    </m.div>
  );
}
