import { useState, useRef, useEffect } from 'react';
import { Activity, Target, FileText, FileJson, Upload, ShieldCheck, Bug, ChevronDown, ChevronRight, Hash, Eye } from 'lucide-react';
import { triggerDownload } from '../utils/download';
import { m, AnimatePresence } from 'framer-motion';

// ── 3D Containment Sandbox Animation ──
function ContainmentSandbox({ isScanning }: { isScanning: boolean }) {
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

    const cubeSize = 100;
    const vertices = [
      [-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1],
      [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1]
    ].map(v => ({ x: v[0] * cubeSize, y: v[1] * cubeSize, z: v[2] * cubeSize }));

    const edges = [
      [0,1],[1,2],[2,3],[3,0],
      [4,5],[5,6],[6,7],[7,4],
      [0,4],[1,5],[2,6],[3,7]
    ];

    const particles: any[] = [];

    const render = () => {
      time += 0.01;
      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;

      // Add particles if scanning
      if (isScanning && Math.random() > 0.5) {
        particles.push({
          x: (Math.random() - 0.5) * cubeSize * 1.5,
          y: -cubeSize * 2,
          z: (Math.random() - 0.5) * cubeSize * 1.5,
          speed: 2 + Math.random() * 2,
          color: Math.random() > 0.8 ? '#FF2A55' : '#00E5FF'
        });
      }

      // Rotate cube
      const rotX = time * 0.4;
      const rotY = time * 0.6;
      const rotZ = Math.sin(time * 0.5) * 0.2;

      const project = (p: {x: number, y: number, z: number}) => {
        // X
        let y1 = p.y * Math.cos(rotX) - p.z * Math.sin(rotX);
        let z1 = p.y * Math.sin(rotX) + p.z * Math.cos(rotX);
        // Y
        let x2 = p.x * Math.cos(rotY) + z1 * Math.sin(rotY);
        let z2 = -p.x * Math.sin(rotY) + z1 * Math.cos(rotY);
        // Z
        let x3 = x2 * Math.cos(rotZ) - y1 * Math.sin(rotZ);
        let y3 = x2 * Math.sin(rotZ) + y1 * Math.cos(rotZ);
        
        return { x: cx + x3, y: cy + y3, z: z2 };
      };

      const projVertices = vertices.map(project);

      // Draw cube edges
      ctx.lineWidth = isScanning ? 1.5 : 0.5;
      edges.forEach(([i, j]) => {
        const p1 = projVertices[i];
        const p2 = projVertices[j];
        const zMid = (p1.z + p2.z) / 2;
        const alpha = Math.max(0.1, (zMid + cubeSize * 2) / (cubeSize * 4));
        
        ctx.strokeStyle = isScanning 
          ? `rgba(0, 229, 255, ${alpha + 0.2 + Math.sin(time*10)*0.2})`
          : `rgba(255, 255, 255, ${alpha * 0.5})`;
        
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
      });

      // Draw particles
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.y += p.speed;
        if (p.y > cubeSize * 2) {
          particles.splice(i, 1);
          continue;
        }

        const proj = project(p);
        const scale = Math.max(0.1, (proj.z + cubeSize * 2) / (cubeSize * 4));
        
        ctx.beginPath();
        ctx.arc(proj.x, proj.y, 2 * scale, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.shadowBlur = 10;
        ctx.shadowColor = p.color;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, [isScanning]);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full mix-blend-screen pointer-events-none" />;
}

interface EvidenceDetail {
  id: string;
  summary: string;
  hex_dump: string;
  ascii_dump: string;
}

interface ValidationDetection {
  id: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  message: string;
  mitre_technique?: string;
  mitre_tactic?: string;
  confidence: number;
  evidence_packets: number;
  src_ip: string;
  dst_ip: string;
  proto: string;
  packet_ids: string[];
  evidence_details: EvidenceDetail[];
  threat_score?: number;
  risk_level?: string;
  ioc_hit?: boolean;
  ioc_value?: string;
}

interface ValidationSession {
  session_id: string;
  timestamp: number;
  pcap_name: string;
  packets_processed: number;
  duration_sec: number;
  detections: ValidationDetection[];
  ioc_hits?: ValidationDetection[];
  techniques: string[];
  status: string;
}

export function DetectionValidationLab() {
  const [sessions, setSessions] = useState<ValidationSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const handlePcapUpload = async (file: File) => {
    if (!file.name.match(/\.pcap(ng)?$/i)) return;
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('http://127.0.0.1:8000/api/validation/run', { method: 'POST', body: fd });
      if (res.ok) {
        const data: ValidationSession = await res.json();
        setSessions(prev => [data, ...prev]);
        setSelectedSessionId(data.session_id);
      }
    } catch (e) {
      console.error('Validation run failed:', e);
    } finally {
      setLoading(false);
    }
  };

  const activeSession = sessions.find(s => s.session_id === selectedSessionId);

  const handleExportJson = (session: ValidationSession) => {
    const dataStr = JSON.stringify(session, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    triggerDownload(`validation_${session.session_id}.json`, blob);
  };

  const handleExportCsv = (session: ValidationSession) => {
    const headers = ["Session_ID", "PCAP_File", "Timestamp", "Alert_Category", "Risk_Level", "Threat_Score", "Src_IP", "Dst_IP", "Evidence_Count", "IOC_Hit", "IOC_Value", "MITRE"];
    const rows = session.detections.map(d => [
      session.session_id,
      session.pcap_name,
      session.timestamp,
      d.category,
      d.risk_level || d.severity,
      d.threat_score || 0,
      d.src_ip,
      d.dst_ip,
      d.evidence_packets,
      d.ioc_hit ? 'TRUE' : 'FALSE',
      d.ioc_value || '',
      d.mitre_technique || ''
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    triggerDownload(`validation_${session.session_id}.csv`, blob);
  };

  const handleExportPdf = (session: ValidationSession) => {
    const printWin = window.open('', '', 'width=800,height=600');
    if (!printWin) return;
    printWin.document.write(`
      <html>
        <head>
          <title>Validation Report ${session.session_id}</title>
          <style>
            body { font-family: sans-serif; padding: 20px; color: #333; }
            h1 { color: #111; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background: #f5f5f5; }
            .critical { color: #d32f2f; font-weight: bold; }
          </style>
        </head>
        <body>
          <h1>HexSniff Validation Report</h1>
          <p><strong>Session ID:</strong> ${session.session_id}</p>
          <p><strong>PCAP:</strong> ${session.pcap_name}</p>
          <p><strong>Packets Evaluated:</strong> ${session.packets_processed}</p>
          <p><strong>Correlated IOC Hits:</strong> ${session.ioc_hits?.length || 0}</p>
          <table>
            <thead>
              <tr><th>Risk Level</th><th>Score</th><th>Category</th><th>IOC Value</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              ${session.detections.map(d => `
                <tr>
                  <td class="${d.risk_level === 'CRITICAL' ? 'critical' : ''}">${d.risk_level}</td>
                  <td>${d.threat_score}</td>
                  <td>${d.category}</td>
                  <td>${d.ioc_hit ? d.ioc_value : ''}</td>
                  <td>${d.evidence_packets}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
          <script>window.print(); window.close();</script>
        </body>
      </html>
    `);
    printWin.document.close();
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
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,229,255,0.05)_0%,transparent_70%)] pointer-events-none" />
        <ContainmentSandbox isScanning={loading} />
        
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <Activity size={24} className="text-neon-blue" />
            <h1 className="text-2xl font-bold text-white tracking-wide">Detection Validation Lab</h1>
          </div>
          <p className="text-sm font-sans text-text-muted max-w-lg">
            Strict evidence-driven validation of HexSniff IDS detections. Upload a PCAP to generate an isolated forensic report in the containment sandbox.
          </p>
        </div>

        <div className="relative z-10">
          <input
            ref={fileRef}
            type="file"
            accept=".pcap,.pcapng"
            className="hidden"
            onChange={e => e.target.files?.[0] && handlePcapUpload(e.target.files[0])}
          />
          <button
            className="px-6 py-3 rounded-lg bg-neon-blue/10 border border-neon-blue/30 text-neon-blue hover:bg-neon-blue/20 transition-all shadow-glow-blue flex items-center gap-2 font-bold tracking-wide uppercase text-sm"
            onClick={() => fileRef.current?.click()}
            disabled={loading}
          >
            {loading ? <Bug className="animate-spin" size={16} /> : <Upload size={16} />}
            {loading ? 'Validating Sandbox...' : 'Run PCAP Validation'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* ── Sessions Table ── */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card lg:col-span-1 h-fit">
          <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
            <Hash size={14} className="text-neon-blue" /> Validation Sessions
          </div>
          <div className="p-0 overflow-x-auto min-h-[300px]">
            {sessions.length === 0 ? (
              <div className="p-10 flex flex-col items-center justify-center text-center text-text-muted">
                <ShieldCheck size={36} className="mb-4 opacity-30" />
                <p className="text-sm">No validation sessions run.</p>
              </div>
            ) : (
              <table className="w-full text-left border-collapse whitespace-nowrap">
                <thead>
                  <tr className="bg-white/[0.01] text-[10px] uppercase tracking-wider text-text-muted border-b border-border-dim font-mono">
                    <th className="py-3 px-5 font-medium">Session ID</th>
                    <th className="py-3 px-5 font-medium">Alerts</th>
                  </tr>
                </thead>
                <tbody className="font-mono text-xs">
                  {sessions.map(s => (
                    <tr 
                      key={s.session_id} 
                      onClick={() => setSelectedSessionId(s.session_id)}
                      className={`cursor-pointer border-b border-border-dim/30 transition-colors ${selectedSessionId === s.session_id ? 'bg-neon-blue/10 border-l-2 border-l-neon-blue' : 'hover:bg-white/5'}`}
                    >
                      <td className="py-3 px-5 text-white">{s.session_id.substring(0, 8)}...</td>
                      <td className="py-3 px-5">
                        <span className={`px-2 py-1 rounded-full text-[10px] ${s.detections.length > 0 ? 'bg-crimson/10 text-crimson border border-crimson/30' : 'bg-neon-blue/10 text-neon-blue border border-neon-blue/30'}`}>
                          {s.detections.length}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ── Active Session Details ── */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card lg:col-span-2 min-h-[400px]">
          {activeSession ? (
            <>
              <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02] sticky top-0 z-10">
                <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
                  <Target size={14} className="text-neon-blue" /> Session Forensics
                  <span className="font-mono text-text-muted ml-2">{activeSession.session_id}</span>
                </div>
                <div className="flex gap-2">
                  <button className="p-1.5 rounded hover:bg-white/10 text-text-muted transition-colors" title="Export JSON" onClick={() => handleExportJson(activeSession)}><FileJson size={14} /></button>
                  <button className="p-1.5 rounded hover:bg-white/10 text-text-muted transition-colors" title="Export CSV" onClick={() => handleExportCsv(activeSession)}><Target size={14} /></button>
                  <button className="p-1.5 rounded hover:bg-white/10 text-text-muted transition-colors" title="Export PDF" onClick={() => handleExportPdf(activeSession)}><FileText size={14} /></button>
                </div>
              </div>
              
              <div className="p-6 flex flex-col gap-4 bg-white/[0.01]">
                {/* Stats Row */}
                <div className="grid grid-cols-3 gap-4 mb-2">
                  <div className="p-4 rounded-lg bg-white/5 border border-white/10">
                    <div className="text-[10px] uppercase tracking-widest text-text-muted mb-1 font-mono">PCAP File</div>
                    <div className="text-sm font-semibold text-white truncate">{activeSession.pcap_name}</div>
                  </div>
                  <div className="p-4 rounded-lg bg-white/5 border border-white/10">
                    <div className="text-[10px] uppercase tracking-widest text-text-muted mb-1 font-mono">Packets Processed</div>
                    <div className="text-sm font-semibold text-neon-blue font-mono">{activeSession.packets_processed.toLocaleString()}</div>
                  </div>
                  <div className="p-4 rounded-lg bg-white/5 border border-white/10">
                    <div className="text-[10px] uppercase tracking-widest text-text-muted mb-1 font-mono">Total Duration</div>
                    <div className="text-sm font-semibold text-white font-mono">{activeSession.duration_sec.toFixed(2)}s</div>
                  </div>
                </div>

                {/* Benchmarking Metrics */}
                <div className="p-5 rounded-xl bg-black/20 border border-border-dim shadow-inner mb-2 flex flex-col gap-3">
                  <div className="flex items-center gap-2 text-xs font-bold text-white uppercase tracking-wider mb-2">
                    <Activity size={14} className="text-emerald-400" /> Detection Benchmark
                  </div>
                  <div className="grid grid-cols-4 gap-4">
                    <div>
                      <div className="text-[10px] text-text-muted uppercase font-sans mb-1">Rules Triggered</div>
                      <div className="text-lg font-mono text-crimson font-bold">{activeSession.detections.length}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-text-muted uppercase font-sans mb-1">MITRE Techniques</div>
                      <div className="text-lg font-mono text-orange-400 font-bold">{activeSession.techniques?.length || 0}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-text-muted uppercase font-sans mb-1">Avg Confidence</div>
                      <div className="text-lg font-mono text-neon-blue font-bold">
                        {activeSession.detections.length > 0 
                          ? Math.round(activeSession.detections.reduce((sum, d) => sum + d.confidence, 0) / activeSession.detections.length) + '%' 
                          : 'N/A'}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-text-muted uppercase font-sans mb-1">False Positive Risk</div>
                      <div className="text-lg font-mono text-yellow-400 font-bold">
                        {activeSession.detections.filter(d => d.confidence < 70).length} Alerts
                      </div>
                    </div>
                  </div>
                </div>

                {activeSession.detections.length === 0 ? (
                  <div className="p-10 flex flex-col items-center justify-center text-center text-neon-blue bg-neon-blue/5 border border-neon-blue/20 rounded-xl">
                    <ShieldCheck size={36} className="mb-4 opacity-50" />
                    <p className="font-bold tracking-wide">Traffic is Clean</p>
                    <p className="text-sm opacity-80 mt-1">Zero malicious signatures detected in payload.</p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-3">
                    {activeSession.detections.map((det, i) => {
                      const isExpanded = expandedAlertId === det.id + i;
                      const isCritical = det.risk_level === 'CRITICAL' || det.severity === 'Critical';
                      
                      return (
                        <div key={det.id + i} className={`rounded-xl border overflow-hidden transition-all duration-300 ${isCritical ? 'border-crimson/30 bg-crimson/5' : 'border-white/10 bg-white/[0.02]'}`}>
                          
                          {/* Alert Header */}
                          <div 
                            className="px-4 py-3 cursor-pointer flex items-center justify-between hover:bg-white/5 transition-colors"
                            onClick={() => setExpandedAlertId(isExpanded ? null : det.id + i)}
                          >
                            <div className="flex items-center gap-3">
                              {isExpanded ? <ChevronDown size={14} className="text-text-muted" /> : <ChevronRight size={14} className="text-text-muted" />}
                              <span className={`font-semibold text-sm ${isCritical ? 'text-crimson' : 'text-white'}`}>{det.category}</span>
                            </div>
                            <div className="flex items-center gap-3">
                              {det.ioc_hit && <span className="px-2 py-0.5 rounded text-[10px] bg-crimson/20 text-crimson font-mono border border-crimson/30">IOC MATCH</span>}
                              <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${isCritical ? 'bg-crimson/20 border-crimson/30 text-crimson' : 'bg-white/10 border-white/20 text-text-muted'}`}>
                                SCORE: {det.threat_score}
                              </span>
                            </div>
                          </div>
                          
                          {/* Alert Expanded Content */}
                          <AnimatePresence>
                            {isExpanded && (
                              <m.div 
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                className="border-t border-border-dim overflow-hidden"
                              >
                                <div className="p-4 flex flex-col gap-4">
                                  <div className="text-sm text-text-muted leading-relaxed">
                                    <strong className="text-white">Analysis:</strong> {det.message}
                                  </div>

                                  <div className="grid grid-cols-3 gap-4 p-3 rounded bg-black/20 border border-white/5 font-mono text-xs">
                                    <div><span className="text-text-muted mr-2">SRC</span><span className="text-neon-blue">{det.src_ip}</span></div>
                                    <div><span className="text-text-muted mr-2">DST</span><span className="text-neon-blue">{det.dst_ip}</span></div>
                                    <div><span className="text-text-muted mr-2">PRT</span><span className="text-white">{det.proto}</span></div>
                                  </div>

                                  {/* Evidence Viewer */}
                                  {det.evidence_details && det.evidence_details.length > 0 && (
                                    <div className="flex flex-col gap-2 mt-2">
                                      <div className="flex items-center gap-2 text-xs font-semibold text-neon-blue">
                                        <Eye size={12} /> Forensic Payload Extracts ({det.evidence_details.length})
                                      </div>
                                      {det.evidence_details.map((ev, ei) => (
                                        <div key={ei} className="p-3 rounded border border-white/5 bg-black/40 font-mono text-[10px]">
                                          <div className="text-green-400 mb-2 font-bold opacity-80">ID: {ev.id} | {ev.summary}</div>
                                          <div className="grid grid-cols-2 gap-4">
                                            <div className="text-text-muted whitespace-pre-wrap max-h-32 overflow-y-auto custom-scrollbar">{ev.hex_dump || 'No hex dump'}</div>
                                            <div className="text-purple-400 whitespace-pre-wrap max-h-32 overflow-y-auto custom-scrollbar break-all">{ev.ascii_dump || 'No payload'}</div>
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </m.div>
                            )}
                          </AnimatePresence>

                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-10 text-center text-text-muted">
              <Activity size={36} className="mb-4 opacity-20" />
              <p className="text-sm max-w-sm">Select a validation session from the list to view detailed forensic reports and evidence dumps.</p>
            </div>
          )}
        </div>
      </div>
    </m.div>
  );
}
