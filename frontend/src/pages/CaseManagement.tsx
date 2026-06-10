import { useState, useEffect } from 'react';
import { m } from 'framer-motion';
import { Database, FolderOpen, ShieldAlert, Clock, Tag, FileText, Search, Activity } from 'lucide-react';

interface CaseInfo {
  case_id: string;
  title: string;
  status: string;
  severity: string;
  tags: string;
  created_at: number;
  updated_at: number;
}

interface CaseDetails extends CaseInfo {
  notes: string;
  evidence: Array<{
    evidence_id: string;
    packet_id: string;
    alert_id: string;
    ioc: string;
    mitre_technique: string;
    mitre_tactic: string;
  }>;
  timeline: Array<{
    event_id: string;
    timestamp: number;
    event_type: string;
    description: string;
  }>;
}

export function CaseManagement() {
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [selectedCase, setSelectedCase] = useState<CaseDetails | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [filter, setFilter] = useState('');

  const fetchCases = () => {
    setIsLoading(true);
    fetch('http://127.0.0.1:8000/api/cases')
      .then(res => res.json())
      .then(data => {
        setCases(data);
        setIsLoading(false);
      })
      .catch(err => {
        console.error(err);
        setIsLoading(false);
      });
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const selectCase = (caseId: string) => {
    fetch(`http://127.0.0.1:8000/api/cases/${caseId}`)
      .then(res => res.json())
      .then(data => setSelectedCase(data))
      .catch(console.error);
  };

  const updateCase = (updates: Partial<{ status: string, severity: string, tags: string, notes: string }>) => {
    if (!selectedCase) return;
    const cid = selectedCase.case_id;
    
    // Optimistic UI update
    setSelectedCase(prev => prev ? { ...prev, ...updates } : null);
    setCases(prev => prev.map(c => c.case_id === cid ? { ...c, ...updates } : c));

    fetch(`http://127.0.0.1:8000/api/cases/${cid}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    })
    .catch(console.error);
  };

  const fmt = (ts: number) => new Date(ts * 1000).toLocaleString();

  const filteredCases = filter.trim()
    ? cases.filter(c => 
        c.title.toLowerCase().includes(filter.toLowerCase()) || 
        c.case_id.toLowerCase().includes(filter.toLowerCase()) ||
        c.tags.toLowerCase().includes(filter.toLowerCase())
      )
    : cases;

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex gap-6 h-full max-w-[1800px] mx-auto pb-6"
    >
      {/* ── Left Column: Case List ── */}
      <div className="flex flex-col gap-6 w-1/3 min-w-[350px]">
        <div className="glass-panel rounded-2xl shadow-card flex flex-col h-full overflow-hidden">
          <div className="p-5 border-b border-border-dim bg-black/20 shrink-0">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-8 h-8 rounded-full bg-neon-blue/10 border border-neon-blue/30 flex items-center justify-center">
                <Database size={16} className="text-neon-blue" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-widest text-glow-blue">Active Cases</h2>
                <div className="text-[10px] text-text-muted">Enterprise Investigation Vault</div>
              </div>
            </div>
            
            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
              <input 
                value={filter} 
                onChange={e => setFilter(e.target.value)} 
                placeholder="Search cases..." 
                className="w-full bg-void border border-border-dim rounded-lg pl-9 pr-4 py-2 text-xs text-white focus:border-neon-blue outline-none transition-all"
              />
            </div>
          </div>

          <div className="flex-1 overflow-auto custom-scrollbar p-2">
            {isLoading ? (
              <div className="p-4 text-center text-text-muted text-xs uppercase tracking-widest">Loading cases...</div>
            ) : filteredCases.length === 0 ? (
              <div className="p-4 text-center text-text-muted text-xs uppercase tracking-widest">No cases found</div>
            ) : (
              <div className="flex flex-col gap-2">
                {filteredCases.map(c => {
                  const isSelected = selectedCase?.case_id === c.case_id;
                  return (
                    <div 
                      key={c.case_id}
                      onClick={() => selectCase(c.case_id)}
                      className={`p-3 rounded-lg border transition-all cursor-pointer ${
                        isSelected 
                          ? 'bg-neon-blue/10 border-neon-blue/50 shadow-glow-blue' 
                          : 'bg-void border-border-dim hover:border-text-muted/50 hover:bg-surface-active'
                      }`}
                    >
                      <div className="flex justify-between items-start mb-2">
                        <div className="font-bold text-xs text-white uppercase tracking-wider truncate mr-2">
                          {c.title}
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-widest whitespace-nowrap ${
                          c.status === 'Open' ? 'bg-emerald/20 text-emerald' :
                          c.status === 'Closed' ? 'bg-text-muted/20 text-text-muted' :
                          'bg-amber-500/20 text-amber-500'
                        }`}>
                          {c.status}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-3 text-[10px] text-text-muted mb-2 font-mono">
                        <span className="truncate" title={c.case_id}>ID: {c.case_id.split('-')[0]}</span>
                        <span className="flex items-center gap-1"><Clock size={10} /> {new Date(c.updated_at * 1000).toLocaleDateString()}</span>
                      </div>

                      <div className="flex items-center gap-2">
                         <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                           c.severity === 'Critical' ? 'bg-crimson/20 text-crimson border border-crimson/30' :
                           c.severity === 'High' ? 'bg-orange-500/20 text-orange-500 border border-orange-500/30' :
                           'bg-neon-blue/20 text-neon-blue border border-neon-blue/30'
                         }`}>
                           {c.severity}
                         </span>
                         {c.tags && (
                           <span className="text-[9px] text-text-muted truncate">
                             <Tag size={8} className="inline mr-1" /> {c.tags}
                           </span>
                         )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Right Column: Case Details ── */}
      <div className="flex-1 flex flex-col min-w-0 h-full">
        {selectedCase ? (
          <div className="glass-panel rounded-2xl shadow-card flex flex-col h-full overflow-hidden">
            {/* Header */}
            <div className="p-6 border-b border-border-dim bg-black/20 shrink-0">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <div className="text-[10px] text-text-muted font-mono uppercase tracking-widest mb-1">
                    Case ID: {selectedCase.case_id}
                  </div>
                  <h1 className="text-xl font-display font-bold text-white tracking-wide">
                    {selectedCase.title}
                  </h1>
                </div>
                <div className="flex gap-2">
                   <select 
                     value={selectedCase.status}
                     onChange={e => updateCase({ status: e.target.value })}
                     className="bg-void border border-border-dim text-white text-xs p-2 rounded outline-none font-bold uppercase tracking-widest"
                   >
                     <option value="Open">Open</option>
                     <option value="Investigating">Investigating</option>
                     <option value="Resolved">Resolved</option>
                     <option value="Closed">Closed</option>
                   </select>
                   <select 
                     value={selectedCase.severity}
                     onChange={e => updateCase({ severity: e.target.value })}
                     className={`bg-void border border-border-dim text-xs p-2 rounded outline-none font-bold uppercase tracking-widest ${
                       selectedCase.severity === 'Critical' ? 'text-crimson' :
                       selectedCase.severity === 'High' ? 'text-orange-500' : 'text-neon-blue'
                     }`}
                   >
                     <option value="Critical">Critical</option>
                     <option value="High">High</option>
                     <option value="Medium">Medium</option>
                     <option value="Low">Low</option>
                   </select>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Tag size={12} className="text-text-muted" />
                <input 
                  value={selectedCase.tags}
                  onChange={e => updateCase({ tags: e.target.value })}
                  placeholder="Comma-separated tags (e.g. ransomware, apt29, phishing)"
                  className="bg-transparent border-none text-xs text-text-muted flex-1 outline-none font-mono"
                />
              </div>
            </div>

            <div className="flex-1 overflow-auto custom-scrollbar p-6 flex flex-col gap-6">
              
              {/* Investigation Notes */}
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest border-b border-border-dim pb-2">
                  <FileText size={14} className="text-neon-blue" />
                  Investigation Notes
                </div>
                <textarea 
                  value={selectedCase.notes || ''}
                  onChange={e => updateCase({ notes: e.target.value })}
                  placeholder="Enter analyst notes, findings, and hypotheses here..."
                  className="w-full h-32 bg-void border border-border-dim text-sm text-text-main p-3 rounded-lg outline-none focus:border-neon-blue transition-all custom-scrollbar"
                />
              </div>

              {/* Linked Evidence */}
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest border-b border-border-dim pb-2">
                  <ShieldAlert size={14} className="text-crimson" />
                  Linked Evidence ({selectedCase.evidence?.length || 0})
                </div>
                {selectedCase.evidence && selectedCase.evidence.length > 0 ? (
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-3 mt-2">
                    {selectedCase.evidence.map(ev => (
                      <div key={ev.evidence_id} className="bg-void border border-border-dim p-3 rounded-lg flex flex-col gap-2">
                        {ev.packet_id && (
                          <div className="text-[10px] font-mono text-text-muted">
                            <span className="text-white">Packet:</span> {ev.packet_id}
                          </div>
                        )}
                        {ev.alert_id && (
                          <div className="text-[10px] font-mono text-text-muted">
                            <span className="text-crimson font-bold">Alert:</span> {ev.alert_id}
                          </div>
                        )}
                        {ev.ioc && (
                          <div className="text-[10px] font-mono text-text-muted">
                            <span className="text-orange-500 font-bold">IOC:</span> {ev.ioc}
                          </div>
                        )}
                        {(ev.mitre_tactic || ev.mitre_technique) && (
                          <div className="flex gap-2 mt-1">
                            {ev.mitre_tactic && <span className="px-1.5 py-0.5 bg-white/5 border border-white/10 text-[9px] font-bold rounded">{ev.mitre_tactic}</span>}
                            {ev.mitre_technique && <span className="px-1.5 py-0.5 bg-white/5 border border-white/10 text-[9px] font-mono text-emerald rounded">{ev.mitre_technique}</span>}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-text-muted italic py-4">No evidence linked to this case yet.</div>
                )}
              </div>

              {/* Case Timeline */}
              <div className="flex flex-col gap-2 mt-4">
                <div className="flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest border-b border-border-dim pb-2">
                  <Activity size={14} className="text-emerald" />
                  Audit Timeline
                </div>
                <div className="flex flex-col gap-0 mt-2">
                  {selectedCase.timeline && selectedCase.timeline.map((evt, idx) => (
                    <div key={evt.event_id} className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <div className="w-2 h-2 rounded-full bg-emerald shadow-glow-emerald mt-1.5"></div>
                        {idx < selectedCase.timeline.length - 1 && <div className="w-[1px] h-full bg-border-dim my-1"></div>}
                      </div>
                      <div className="pb-6">
                        <div className="text-[10px] text-text-muted font-mono mb-1">{fmt(evt.timestamp)}</div>
                        <div className="text-xs font-bold text-white mb-0.5">{evt.event_type.replace(/_/g, ' ')}</div>
                        <div className="text-[11px] text-text-main">{evt.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>
        ) : (
          <div className="glass-panel rounded-2xl shadow-card h-full flex flex-col items-center justify-center text-center p-10">
            <FolderOpen size={48} className="text-text-muted mb-4 opacity-50" />
            <h3 className="text-lg font-bold text-white mb-2">No Case Selected</h3>
            <p className="text-sm text-text-muted max-w-md">
              Select a case from the list to view its details, update its status, manage evidence, and track its investigation timeline.
            </p>
          </div>
        )}
      </div>
    </m.div>
  );
}
