import { useEffect, useRef, useState } from 'react';
import { Target, BarChart2, CheckCircle, AlertTriangle, ShieldAlert, History, Download, Activity } from 'lucide-react';
import { useStore, store } from '../store';
import { m } from 'framer-motion';
import { triggerDownload } from '../utils/download';

// ── 3D Threat Matrix Animation ──
function ThreatMatrixCanvas({ coveragePct }: { coveragePct: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = canvas.width = canvas.offsetWidth;
    let height = canvas.height = canvas.offsetHeight;
    let animationFrameId: number;
    let time = 0;

    const handleResize = () => {
      width = canvas.width = canvas.offsetWidth;
      height = canvas.height = canvas.offsetHeight;
    };
    window.addEventListener('resize', handleResize);

    const gridSize = 25;
    const cols = 20;
    const rows = 15;
    const grid: {x: number, z: number, y: number, isCoverage: boolean}[] = [];

    // Initialize grid
    for (let z = 0; z < rows; z++) {
      for (let x = 0; x < cols; x++) {
        grid.push({
          x: (x - cols/2) * gridSize,
          z: (z - rows/2) * gridSize,
          y: 0,
          isCoverage: Math.random() < coveragePct
        });
      }
    }

    const render = () => {
      time += 0.02;
      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2 + 50; // shift down

      // Calculate heights based on Perlin-like wave
      grid.forEach(p => {
        const dist = Math.sqrt(p.x * p.x + p.z * p.z);
        p.y = Math.sin(dist * 0.05 - time) * 15;
        if (p.isCoverage) {
          p.y -= Math.sin(time * 2 + p.x) * 5; // Extra ripple for coverage nodes
        }
      });

      // Projection and rotation
      const rotX = 0.8; // tilt forward
      const rotY = Math.sin(time * 0.2) * 0.1; // slight yaw

      const project = (p: {x: number, y: number, z: number}) => {
        // Rotate Y
        let x1 = p.x * Math.cos(rotY) + p.z * Math.sin(rotY);
        let z1 = -p.x * Math.sin(rotY) + p.z * Math.cos(rotY);
        // Rotate X
        let y2 = p.y * Math.cos(rotX) - z1 * Math.sin(rotX);
        let z2 = p.y * Math.sin(rotX) + z1 * Math.cos(rotX);
        
        return { x: cx + x1, y: cy + y2, z: z2 };
      };

      const projGrid = grid.map(p => ({ ...p, proj: project(p) }));

      // Draw lines
      ctx.lineWidth = 1;
      for (let z = 0; z < rows; z++) {
        for (let x = 0; x < cols; x++) {
          const i = z * cols + x;
          const p = projGrid[i];
          
          if (x < cols - 1) {
            const pRight = projGrid[i + 1];
            ctx.beginPath();
            ctx.moveTo(p.proj.x, p.proj.y);
            ctx.lineTo(pRight.proj.x, pRight.proj.y);
            const alpha = Math.max(0, 1 - (p.proj.z + 200) / 400);
            ctx.strokeStyle = p.isCoverage || pRight.isCoverage 
              ? `rgba(0, 229, 255, ${alpha})`
              : `rgba(255, 255, 255, ${alpha * 0.15})`;
            ctx.stroke();
          }

          if (z < rows - 1) {
            const pDown = projGrid[i + cols];
            ctx.beginPath();
            ctx.moveTo(p.proj.x, p.proj.y);
            ctx.lineTo(pDown.proj.x, pDown.proj.y);
            const alpha = Math.max(0, 1 - (p.proj.z + 200) / 400);
            ctx.strokeStyle = p.isCoverage || pDown.isCoverage 
              ? `rgba(0, 229, 255, ${alpha})`
              : `rgba(255, 255, 255, ${alpha * 0.15})`;
            ctx.stroke();
          }

          // Draw coverage nodes
          if (p.isCoverage) {
            const alpha = Math.max(0, 1 - (p.proj.z + 200) / 400);
            ctx.beginPath();
            ctx.arc(p.proj.x, p.proj.y, 1.5, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0, 229, 255, ${alpha})`;
            ctx.shadowBlur = 8;
            ctx.shadowColor = '#00E5FF';
            ctx.fill();
            ctx.shadowBlur = 0;
          }
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, [coveragePct]);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full mix-blend-screen pointer-events-none" />;
}

export function DetectionEngineering() {
  const { coverageStats } = useStore();
  const [rulesContent, setRulesContent] = useState<string>('');
  const [isSaving, setIsSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<{text: string, type: 'success' | 'error'} | null>(null);

  useEffect(() => {
    store.fetchCoverageStats();
    const interval = setInterval(() => store.fetchCoverageStats(), 10000);
    
    // Fetch current rules
    fetch('http://127.0.0.1:8000/api/rules')
      .then(res => res.json())
      .then(data => setRulesContent(data.content))
      .catch(console.error);
      
    return () => clearInterval(interval);
  }, []);

  const handleSaveRules = async () => {
    setIsSaving(true);
    setSaveMessage(null);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: rulesContent })
      });
      if (res.ok) {
        setSaveMessage({ text: 'Rules successfully deployed to matching engine.', type: 'success' });
      } else {
        setSaveMessage({ text: 'Failed to deploy rules.', type: 'error' });
      }
    } catch (e) {
      setSaveMessage({ text: 'Network error saving rules.', type: 'error' });
    }
    setIsSaving(false);
    setTimeout(() => setSaveMessage(null), 3000);
  };

  const handleExport = () => {
    if (!coverageStats) return;
    const stats = coverageStats;
    const lines = [
      "HEXSNIFF MITRE COVERAGE & EFFECTIVENESS REPORT",
      "==============================================",
      `Total Validation Sessions: ${stats.total_validation_runs}`,
      `Overall False Positive Rate: ${stats.fpr}%`,
      `Tactics Covered: ${12 - stats.gaps.length}/12`,
      "",
      "--- MITRE TACTIC COVERAGE ---"
    ];

    Object.entries(stats.coverage_by_tactic).forEach(([tactic, data]) => {
      lines.push(`${tactic}: ${data.detections > 0 ? `COVERED (${data.techniques} techniques, ${data.evidence} evidence packets)` : 'GAP'}`);
    });

    lines.push("", "--- RULE EFFECTIVENESS ---");
    stats.rules.sort((a, b) => b.trigger_count - a.trigger_count).forEach(r => {
      lines.push(`[${r.rule_name}] Hits: ${r.trigger_count + r.validation_hits} | Avg Conf: ${r.confidence_avg}% | Low Conf/FP: ${r.low_conf_count}`);
    });

    triggerDownload(`hexsniff-coverage-${Date.now()}.txt`, lines.join('\n'));
  };

  if (!coverageStats) {
    return (
      <div className="flex justify-center items-center h-full">
        <Activity className="animate-spin text-neon-blue" size={32} />
      </div>
    );
  }

  const { rules, history, coverage_by_tactic, gaps, fpr, total_validation_runs } = coverageStats;
  const tacticsCovered = 12 - gaps.length;
  const coverageRatio = tacticsCovered / 12;

  const getHeatmapColor = (detections: number) => {
    if (detections === 0) return 'rgba(255,255,255,0.02)';
    if (detections < 5) return 'rgba(0,229,255,0.2)';
    if (detections < 20) return 'rgba(0,229,255,0.5)';
    return 'rgba(0,229,255,0.8)';
  };

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.32, 0.72, 0, 1] }}
      className="flex flex-col gap-6 max-w-[1800px] mx-auto pb-10"
    >
      
      {/* ── 3D Hero Section ── */}
      <div className="relative w-full h-[250px] bg-void rounded-2xl border border-border-dim shadow-card overflow-hidden flex items-center justify-between px-10">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(0,229,255,0.08)_0%,transparent_70%)] pointer-events-none" />
        <ThreatMatrixCanvas coveragePct={coverageRatio} />
        
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <Target size={24} className="text-neon-blue" />
            <h1 className="text-2xl font-bold text-white tracking-wide">Detection Engineering</h1>
          </div>
          <p className="text-sm font-sans text-text-muted max-w-lg">
            Evidence-driven MITRE ATT&CK coverage, rule effectiveness, and gap analysis mapped across the 3D threat matrix.
          </p>
        </div>

        <div className="relative z-10">
          <button
            className="px-6 py-3 rounded-lg bg-white/5 border border-white/10 text-white hover:bg-white/10 transition-all flex items-center gap-2 font-bold tracking-wide uppercase text-sm shadow-card"
            onClick={handleExport}
          >
            <Download size={16} /> Export Coverage Report
          </button>
        </div>
      </div>

      {/* ── KPIs ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-panel p-5 rounded-xl flex flex-col gap-1 border-t-2 border-t-neon-blue">
          <div className="flex items-center gap-2 text-xs font-sans text-text-muted mb-2"><BarChart2 size={14} className="text-neon-blue" /> MITRE Coverage</div>
          <div className="flex items-baseline gap-2">
            <div className={`text-3xl font-mono tracking-tight ${gaps.length === 0 ? 'text-green-400' : 'text-white'}`}>{tacticsCovered}</div>
            <div className="text-xs text-text-muted">/12 Tactics</div>
          </div>
        </div>
        <div className="glass-panel p-5 rounded-xl flex flex-col gap-1 border-t-2 border-t-purple-500">
          <div className="flex items-center gap-2 text-xs font-sans text-text-muted mb-2"><CheckCircle size={14} className="text-purple-500" /> Validation Runs</div>
          <div className="text-3xl font-mono tracking-tight text-white">{total_validation_runs}</div>
        </div>
        <div className="glass-panel p-5 rounded-xl flex flex-col gap-1 border-t-2 border-t-orange-500">
          <div className="flex items-center gap-2 text-xs font-sans text-text-muted mb-2"><AlertTriangle size={14} className="text-orange-500" /> False Positive Rate</div>
          <div className={`text-3xl font-mono tracking-tight ${fpr > 15 ? 'text-crimson' : 'text-green-400'}`}>{fpr}%</div>
        </div>
        <div className="glass-panel p-5 rounded-xl flex flex-col gap-1 border-t-2 border-t-blue-500">
          <div className="flex items-center gap-2 text-xs font-sans text-text-muted mb-2"><ShieldAlert size={14} className="text-blue-500" /> Active Rules</div>
          <div className="text-3xl font-mono tracking-tight text-white">{rules.length}</div>
        </div>
      </div>

      {/* ── Heatmap & Gaps ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Heatmap */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card lg:col-span-2">
          <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
            <Target size={14} className="text-neon-blue" /> MITRE ATT&CK Heatmap
          </div>
          <div className="p-5 grid grid-cols-2 md:grid-cols-3 gap-3">
            {Object.entries(coverage_by_tactic).map(([tactic, data]) => (
              <div 
                key={tactic} 
                style={{ 
                  background: getHeatmapColor(data.detections),
                  borderColor: data.detections > 0 ? 'rgba(0,229,255,0.4)' : 'rgba(255,255,255,0.05)',
                }}
                className="border rounded-lg p-3 flex flex-col gap-1 transition-all hover:border-neon-blue"
              >
                <div className={`text-xs font-bold font-sans ${data.detections > 0 ? 'text-white' : 'text-text-muted'}`}>{tactic}</div>
                <div className={`text-[10px] font-mono ${data.detections > 0 ? 'text-neon-blue' : 'text-text-muted/50'}`}>
                  {data.techniques} TECH | {data.detections} HITS
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Gaps */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
          <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
            <AlertTriangle size={14} className="text-crimson" /> Coverage Gaps
          </div>
          <div className="p-5 flex flex-col gap-3">
            {gaps.length === 0 ? (
              <div className="text-center p-6 text-green-400 font-bold border border-green-400/20 bg-green-400/5 rounded-lg">
                Excellent! Zero tactical gaps.
              </div>
            ) : (
              gaps.map(g => (
                <div key={g} className="px-3 py-2 rounded border border-crimson/30 bg-crimson/10 flex items-center justify-between">
                  <span className="text-xs font-bold text-crimson">{g}</span>
                  <span className="text-[10px] font-mono text-crimson opacity-80">0% COVERAGE</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ── Rule Effectiveness Table ── */}
      <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
        <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
          <ShieldAlert size={14} className="text-neon-blue" /> Rule Effectiveness & False Positives
        </div>
        <div className="p-0 overflow-x-auto min-h-[200px]">
          <table className="w-full text-left border-collapse whitespace-nowrap">
            <thead>
              <tr className="bg-white/[0.01] text-[10px] uppercase tracking-wider text-text-muted border-b border-border-dim font-mono">
                <th className="py-3 px-5 font-medium">Rule Name</th>
                <th className="py-3 px-5 font-medium text-right">Total Hits</th>
                <th className="py-3 px-5 font-medium text-right">Val Hits</th>
                <th className="py-3 px-5 font-medium text-right">Evid Pkts</th>
                <th className="py-3 px-5 font-medium">Confidence</th>
                <th className="py-3 px-5 font-medium">FPs Flagged</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs">
              {rules.length === 0 ? (
                <tr><td colSpan={6} className="p-10 text-center text-text-muted">No rules triggered yet.</td></tr>
              ) : (
                rules.sort((a, b) => b.trigger_count + b.validation_hits - (a.trigger_count + a.validation_hits)).map((r, i) => (
                  <tr key={i} className="border-b border-border-dim/30 hover:bg-white/5 transition-colors">
                    <td className="py-3 px-5 font-bold text-white">{r.rule_name}</td>
                    <td className="py-3 px-5 text-right">{r.trigger_count}</td>
                    <td className="py-3 px-5 text-right text-neon-blue">{r.validation_hits}</td>
                    <td className="py-3 px-5 text-right text-purple-400">{r.evidence_packets}</td>
                    <td className="py-3 px-5">
                      <span className={`px-2 py-1 rounded-full text-[10px] border ${r.confidence_avg >= 80 ? 'bg-crimson/10 text-crimson border-crimson/30' : r.confidence_avg >= 60 ? 'bg-orange-500/10 text-orange-500 border-orange-500/30' : 'bg-white/10 text-text-muted border-white/20'}`}>
                        {r.confidence_avg}% AVG
                      </span>
                    </td>
                    <td className="py-3 px-5">
                      <span className={r.low_conf_count > 0 ? 'text-crimson font-bold' : 'text-green-400'}>
                        {r.low_conf_count} FPs
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Validation History ── */}
      <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
        <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
          <History size={14} className="text-neon-blue" /> Validation History Logs
        </div>
        <div className="p-0 overflow-x-auto">
          <table className="w-full text-left border-collapse whitespace-nowrap">
            <thead>
              <tr className="bg-white/[0.01] text-[10px] uppercase tracking-wider text-text-muted border-b border-border-dim font-mono">
                <th className="py-3 px-5 font-medium">Session ID</th>
                <th className="py-3 px-5 font-medium">Date</th>
                <th className="py-3 px-5 font-medium text-right">Detections</th>
                <th className="py-3 px-5 font-medium text-right">Unique Techs</th>
                <th className="py-3 px-5 font-medium">Coverage Impact</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs">
              {history.length === 0 ? (
                <tr><td colSpan={5} className="p-10 text-center text-text-muted">No validation history.</td></tr>
              ) : (
                history.map((h, i) => (
                  <tr key={i} className="border-b border-border-dim/30 hover:bg-white/5 transition-colors">
                    <td className="py-3 px-5 text-neon-blue">{h.session_id}</td>
                    <td className="py-3 px-5 text-text-muted">{new Date(h.date * 1000).toLocaleString()}</td>
                    <td className="py-3 px-5 text-right">{h.detections}</td>
                    <td className="py-3 px-5 text-right">{h.techniques}</td>
                    <td className="py-3 px-5">
                      <span className="px-2 py-1 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30 text-[10px]">
                        +{h.coverage_impact} mapped
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Custom Rule Builder ── */}
      <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
        <div className="px-5 py-4 border-b border-border-dim flex items-center justify-between text-xs font-sans font-semibold text-white bg-white/[0.02]">
          <div className="flex items-center gap-2">
            <ShieldAlert size={14} className="text-purple-500" /> Custom Detection Rules (Sigma/Suricata Engine)
          </div>
          {saveMessage && (
            <div className={`text-[10px] uppercase font-bold tracking-wide ${saveMessage.type === 'success' ? 'text-green-400' : 'text-crimson'}`}>
              {saveMessage.text}
            </div>
          )}
        </div>
        <div className="p-5 flex flex-col gap-4 bg-void/50">
          <p className="text-xs text-text-muted font-sans max-w-3xl">
            Define custom detection logic using Suricata-style syntax. Rules are compiled and injected directly into the O(1) matching engine at runtime without restarting the backend.
          </p>
          <textarea
            value={rulesContent}
            onChange={(e) => setRulesContent(e.target.value)}
            spellCheck={false}
            className="w-full h-[300px] bg-[#0A0A0A] text-green-400 font-mono text-xs p-4 rounded border border-border-dim focus:outline-none focus:border-purple-500 resize-none shadow-inner"
          />
          <div className="flex justify-end">
            <button
              onClick={handleSaveRules}
              disabled={isSaving}
              className="px-6 py-2 rounded bg-purple-500/20 text-purple-400 border border-purple-500/50 hover:bg-purple-500/30 transition-all font-bold text-xs uppercase tracking-wide disabled:opacity-50"
            >
              {isSaving ? 'Deploying...' : 'Deploy to Engine'}
            </button>
          </div>
        </div>
      </div>

    </m.div>
  );
}
