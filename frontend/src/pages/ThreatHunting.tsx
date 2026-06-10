import { useState, useEffect } from 'react';
import { useStore, store } from '../store';
import { ThreatGraph } from '../components/Visuals/ThreatGraph';
import { Search, Brain, Target, ShieldAlert, FolderPlus } from 'lucide-react';
import { m } from 'framer-motion';

export function ThreatHunting() {
  const state = useStore();
  const [nlQuery, setNlQuery] = useState('');
  const [entity, setEntity] = useState('alerts');
  const [paramsStr, setParamsStr] = useState('{"severity": "Critical"}');
  
  useEffect(() => {
    // @ts-ignore
    store.fetchHuntGraph();
  }, []);

  const runStructuredHunt = async () => {
    try {
      const parsed = JSON.parse(paramsStr);
      // @ts-ignore
      await store.executeHunt(entity, parsed);
    } catch (e) {
      alert("Invalid JSON params");
    }
  };

  const runNlHunt = async () => {
    if (!nlQuery.trim()) return;
    // @ts-ignore
    const res = await store.executeNLHunt(nlQuery);
    if (res?.interpreted) {
      setParamsStr(JSON.stringify(res.interpreted, null, 2));
    }
  };

  const createCaseFromHunt = async () => {
    if (!state.huntResults || state.huntResults.length === 0) {
      alert("No results to build a case from.");
      return;
    }

    try {
      // 1. Create Case
      const caseTitle = `Hunt Escalation - ${entity.toUpperCase()} (${new Date().toLocaleString()})`;
      const caseRes = await fetch('http://127.0.0.1:8000/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: caseTitle })
      });
      
      if (!caseRes.ok) throw new Error("Failed to create case");
      const newCase = await caseRes.json();
      
      // 2. Attach Evidence
      for (const row of state.huntResults) {
        // Build payload matching evidence schema
        const payload = {
          packet_id: row.id || row.packet_id || "",
          alert_id: row.alert_id || "",
          ioc: row.ip || row.domain || row.hash || "",
          mitre_technique: row.mitre_technique || "",
          mitre_tactic: row.mitre_tactic || ""
        };
        
        await fetch(`http://127.0.0.1:8000/api/cases/${newCase.case_id}/evidence`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
      }

      alert(`Case ${newCase.case_id.split('-')[0]} created with ${state.huntResults.length} evidence items automatically linked.`);
    } catch (e) {
      console.error(e);
      alert("Error escalating to case. See console for details.");
    }
  };

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex gap-6 h-full max-w-[1800px] mx-auto pb-6"
    >
      {/* ── Left Column: Hunt Query Builder & Results ── */}
      <div className="flex flex-col gap-6 w-1/2 min-w-[500px]">
        
        {/* NL Query Box */}
        <div className="glass-panel p-5 rounded-2xl shadow-card flex flex-col gap-4">
          <div className="flex items-center gap-3 border-b border-border-dim pb-3">
            <div className="w-8 h-8 rounded-full bg-neon-blue/10 border border-neon-blue/30 flex items-center justify-center">
              <Brain size={16} className="text-neon-blue" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-widest text-glow-blue">Natural Language Hunt</h2>
              <div className="text-[10px] text-text-muted">Copilot translates intent into structured queries</div>
            </div>
          </div>
          
          <div className="flex gap-3">
            <input 
              value={nlQuery}
              onChange={e => setNlQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runNlHunt()}
              placeholder="e.g., 'Show all assets communicating with Command and Control'"
              className="flex-1 bg-void border border-border-dim rounded-lg px-4 text-sm text-white focus:border-neon-blue outline-none transition-all"
            />
            <button 
              onClick={runNlHunt}
              disabled={state.isHunting}
              className="px-6 py-2 bg-neon-blue text-void font-bold uppercase tracking-widest text-xs rounded-lg hover:shadow-glow-blue transition-all disabled:opacity-50"
            >
              {state.isHunting ? 'Thinking...' : 'Hunt'}
            </button>
          </div>
        </div>

        {/* Structured Query Box */}
        <div className="glass-panel p-5 rounded-2xl shadow-card flex flex-col gap-4">
           <div className="flex items-center justify-between border-b border-border-dim pb-3">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-emerald/10 border border-emerald/30 flex items-center justify-center">
                <Target size={16} className="text-emerald" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-widest text-glow-emerald">Structured Hunt</h2>
              </div>
            </div>
          </div>

          <div className="flex gap-4">
            <div className="flex-1 flex flex-col gap-2">
               <label className="text-[10px] uppercase tracking-widest text-text-muted font-bold">Entity Type</label>
               <select 
                 value={entity} 
                 onChange={e => setEntity(e.target.value)}
                 className="bg-void border border-border-dim text-white text-xs p-2 rounded outline-none"
               >
                 <option value="alerts">Alerts</option>
                 <option value="assets">Assets</option>
                 <option value="attack_chains">Attack Chains</option>
                 <option value="cases">Cases</option>
                 <option value="mitre">MITRE Coverage</option>
               </select>
            </div>
            <div className="flex-[3] flex flex-col gap-2">
               <label className="text-[10px] uppercase tracking-widest text-text-muted font-bold">Query Parameters (JSON)</label>
               <textarea 
                 value={paramsStr}
                 onChange={e => setParamsStr(e.target.value)}
                 className="bg-void border border-border-dim text-neon-blue font-mono text-xs p-3 rounded outline-none h-24 custom-scrollbar"
               />
            </div>
          </div>
          
          <div className="flex justify-end gap-3 mt-2">
            <button 
              onClick={runStructuredHunt}
              disabled={state.isHunting}
              className="px-6 py-2 bg-surface-active border border-border-bright text-white font-bold uppercase tracking-widest text-xs rounded-lg hover:bg-white/10 transition-all disabled:opacity-50 flex items-center gap-2"
            >
              <Search size={14} /> {state.isHunting ? 'Executing...' : 'Execute Structured'}
            </button>
          </div>
        </div>

        {/* Results Data Table */}
        <div className="glass-panel rounded-2xl shadow-card flex-1 flex flex-col overflow-hidden min-h-[300px]">
          <div className="p-4 border-b border-border-dim flex justify-between items-center bg-black/20 shrink-0">
             <div className="flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest">
                <ShieldAlert size={14} className="text-crimson text-glow-red" />
                Hunt Evidence ({state.huntResults?.length || 0})
             </div>
             
             {state.huntResults && state.huntResults.length > 0 && (
                <button 
                  onClick={createCaseFromHunt}
                  className="px-3 py-1.5 bg-crimson/10 border border-crimson/30 text-crimson hover:bg-crimson hover:text-white font-bold uppercase tracking-widest text-[10px] rounded flex items-center gap-2 transition-all shadow-glow-red"
                >
                  <FolderPlus size={12} /> Escalate to Case
                </button>
             )}
          </div>
          
          <div className="flex-1 overflow-auto custom-scrollbar p-0">
             {state.isHunting ? (
               <div className="h-full flex items-center justify-center text-text-muted uppercase tracking-widest text-xs">Scanning Database...</div>
             ) : !state.huntResults || state.huntResults.length === 0 ? (
               <div className="h-full flex items-center justify-center text-text-muted uppercase tracking-widest text-xs">No evidence found</div>
             ) : (
               <table className="w-full text-left border-collapse">
                 <thead className="bg-void sticky top-0 z-10 shadow-md">
                   <tr>
                     {Object.keys(state.huntResults[0]).map(k => (
                       <th key={k} className="p-3 border-b border-border-dim text-[10px] uppercase tracking-widest font-bold text-text-muted">{k}</th>
                     ))}
                   </tr>
                 </thead>
                 <tbody>
                   {state.huntResults.map((row: any, i: number) => (
                     <tr key={i} className="hover:bg-white/5 transition-colors border-b border-border-dim/50 group">
                       {Object.values(row).map((val: any, j: number) => (
                         <td key={j} className="p-3 text-xs font-mono text-white max-w-[200px] truncate">
                           {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                         </td>
                       ))}
                     </tr>
                   ))}
                 </tbody>
               </table>
             )}
          </div>
        </div>
      </div>

      {/* ── Right Column: Threat Graph ── */}
      <div className="flex-1 flex flex-col min-w-0">
         <ThreatGraph />
      </div>

    </m.div>
  );
}
