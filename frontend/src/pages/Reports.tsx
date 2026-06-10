import { useState, useRef, useEffect } from 'react';
import { FileText, Download, Trophy, Shield, Activity, Share2 } from 'lucide-react';
import { useStore } from '../store';
import { triggerDownload } from '../utils/download';
import jsPDF from 'jspdf';
import { m } from 'framer-motion';

const ACHIEVEMENTS = [
  { id: 'first_capture', icon: '🎯', name: 'First Capture', desc: 'Started first live capture' },
  { id: 'simulator', icon: '⚗️', name: 'Lab Verified', desc: 'Used the Detection Validation Lab' },
  { id: 'first_alert', icon: '🚨', name: 'First Alert', desc: 'IDS triggered first alert' },
  { id: 'threat_hunter', icon: '🦊', name: 'Threat Hunter', desc: 'Accumulated 10+ alerts' },
  { id: 'packet_collector', icon: '📦', name: 'Packet Collector', desc: 'Captured 100+ packets' },
  { id: 'dns_expert', icon: '🔍', name: 'DNS Expert', desc: 'Captured 10+ DNS queries' },
  { id: 'pcap_analyst', icon: '📁', name: 'PCAP Analyst', desc: 'Uploaded a PCAP file' },
  { id: 'network_guardian', icon: '🛡️', name: 'Network Guardian', desc: 'Complete all scenarios' },
];

// ── 3D Cryptographic Disk Animation ──
function CryptoDiskCanvas() {
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

    const render = () => {
      time += 0.02;
      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;
      
      const rotX = 1.0; // Isotropic tilt
      
      const drawRing = (radius: number, segments: number, speed: number, isDashed: boolean, colorBase: string) => {
        ctx.beginPath();
        const rotOffset = time * speed;
        for (let i = 0; i <= segments; i++) {
          const angle = (i / segments) * Math.PI * 2 + rotOffset;
          const x = Math.cos(angle) * radius;
          const z = Math.sin(angle) * radius;
          
          // apply X rotation to make it a disk in 3D
          const projY = z * Math.sin(rotX);
          
          if (i === 0) ctx.moveTo(cx + x, cy + projY);
          else {
            if (isDashed && i % 2 === 0) {
              ctx.moveTo(cx + x, cy + projY);
            } else {
              ctx.lineTo(cx + x, cy + projY);
            }
          }
        }
        ctx.lineWidth = isDashed ? 3 : 1;
        ctx.strokeStyle = colorBase;
        ctx.stroke();
      };

      ctx.shadowBlur = 10;
      
      // Draw multiple rings of the data platter
      ctx.shadowColor = '#00E5FF';
      drawRing(120, 60, 0.5, true, 'rgba(0, 229, 255, 0.5)');
      drawRing(100, 60, -0.3, false, 'rgba(0, 229, 255, 0.3)');
      drawRing(80, 40, 0.8, true, 'rgba(0, 229, 255, 0.8)');
      
      ctx.shadowColor = '#FF2A55';
      drawRing(60, 30, -1.0, true, 'rgba(255, 42, 85, 0.6)');
      drawRing(40, 20, 0.2, false, 'rgba(255, 42, 85, 0.4)');
      
      // Draw center core
      ctx.beginPath();
      ctx.arc(cx, cy, 10, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
      ctx.shadowColor = '#FFF';
      ctx.shadowBlur = 15;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Draw floating data blocks emitting from center
      const numBlocks = 6;
      for (let i = 0; i < numBlocks; i++) {
        const offsetAngle = (i / numBlocks) * Math.PI * 2 + time * 0.5;
        const dist = 20 + ((time * 20 + i * 20) % 100);
        const x = Math.cos(offsetAngle) * dist;
        const z = Math.sin(offsetAngle) * dist;
        const projY = z * Math.sin(rotX);
        
        const alpha = Math.max(0, 1 - dist / 120);
        ctx.beginPath();
        ctx.arc(cx + x, cy + projY, 3, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 229, 255, ${alpha})`;
        ctx.fill();
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full mix-blend-screen pointer-events-none" />;
}

export function Reports() {
  const { packets, alerts, protocolCounts, totalPackets, achievements } = useStore();
  const [exporting, setExporting] = useState<string | null>(null);

  const exportCSV = () => {
    setExporting('csv');
    const headers = ['Detection', 'Severity', 'Confidence', 'Threat Score', 'Risk Level', 'MITRE Technique', 'MITRE Tactic', 'Evidence Packets', 'IOC Matches', 'Source IP', 'Destination IP'];
    const rows = alerts.map(a => [
      `"${a.category.replace(/"/g, '""')}"`,
      a.severity,
      a.confidence || 0,
      a.threat_score || 0,
      a.risk_level || 'LOW',
      a.mitre_technique || '',
      a.mitre_tactic || '',
      a.evidence_packets || 1,
      a.ioc_hit ? 'TRUE' : 'FALSE',
      a.src_ip || '',
      a.dst_ip || ''
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    triggerDownload(`hexsniff-alerts-${Date.now()}.csv`, csv);
    setExporting(null);
  };

  const exportJSON = () => {
    setExporting('json');
    const data = { exportedAt: new Date().toISOString(), summary: { totalPackets, alertCount: alerts.length, protocolCounts }, packets, alerts };
    triggerDownload(`hexsniff-report-${Date.now()}.json`, JSON.stringify(data, null, 2));
    setExporting(null);
  };

  const exportPCAP = async () => {
    setExporting('pcap');
    try {
      const res = await fetch('http://127.0.0.1:8000/api/download-pcap');
      if (res.ok) {
        // @ts-ignore
        if (window.pywebview && window.pywebview.api) {
          await triggerDownload(`hexsniff-capture-${Date.now()}.pcap`, new Blob(), true);
        } else {
          const blob = await res.blob();
          await triggerDownload(`hexsniff-capture-${Date.now()}.pcap`, blob, true);
        }
      }
    } catch (e) {
      console.error(e);
    }
    setExporting(null);
  };

  const exportPDF = async () => {
    setExporting('pdf');
    try {
      const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
      const now = new Date().toLocaleString();

      doc.setFillColor(6, 12, 20);
      doc.rect(0, 0, 210, 50, 'F');
      doc.setTextColor(56, 139, 253);
      doc.setFontSize(22);
      doc.setFont('helvetica', 'bold');
      doc.text('HEXSNIFF', 20, 22);
      doc.setTextColor(200, 200, 200);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.text('Network Packet Analyzer | Security Report', 20, 30);
      doc.text(`Generated: ${now}`, 20, 38);

      doc.setFillColor(12, 22, 42);
      doc.rect(0, 50, 210, 28, 'F');
      doc.setTextColor(200, 200, 200);
      doc.setFontSize(9);

      const stats = [
        { label: 'Total Packets', val: totalPackets.toString() },
        { label: 'Total Alerts', val: alerts.length.toString() },
        { label: 'High Severity', val: alerts.filter(a => a.severity === 'High').length.toString() },
        { label: 'TCP Packets', val: (protocolCounts['TCP'] || 0).toString() },
        { label: 'UDP Packets', val: (protocolCounts['UDP'] || 0).toString() },
        { label: 'DNS Queries', val: (protocolCounts['DNS'] || 0).toString() },
      ];
      stats.forEach(({ label, val }, i) => {
        const x = 15 + (i % 3) * 65;
        const y = 62 + Math.floor(i / 3) * 10;
        doc.setTextColor(139, 148, 158);
        doc.setFontSize(7);
        doc.text(label.toUpperCase(), x, y);
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(11);
        doc.text(val, x, y + 5);
      });

      doc.setTextColor(239, 68, 68);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      let y = 95;
      doc.text('Executive Summary', 20, y);
      y += 8;
      
      doc.setTextColor(200, 200, 200);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      const iocCount = alerts.filter(a => a.ioc_hit).length;
      const criticalCount = alerts.filter(a => a.risk_level === 'CRITICAL').length;
      const maxScore = alerts.length ? Math.max(...alerts.map(a => a.threat_score || 0)) : 0;
      doc.text(`This capture session analyzed ${totalPackets} packets and detected ${alerts.length} security events.`, 20, y);
      y += 6;
      doc.text(`- Critical Detections: ${criticalCount}`, 20, y);
      y += 6;
      doc.text(`- Peak Threat Score: ${maxScore}/100`, 20, y);
      y += 6;
      doc.text(`- Confirmed IOC Matches: ${iocCount}`, 20, y);
      y += 12;

      doc.setTextColor(239, 68, 68);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('Threat Score Summary', 20, y);
      y += 8;
      doc.setTextColor(200, 200, 200);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.text(`Average Threat Score: ${alerts.length ? Math.round(alerts.reduce((acc, a) => acc + (a.threat_score || 0), 0) / alerts.length) : 0}`, 20, y);
      y += 12;

      doc.setTextColor(239, 68, 68);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('MITRE ATT&CK Summary', 20, y);
      y += 8;
      doc.setTextColor(200, 200, 200);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      const tactics = [...new Set(alerts.map(a => a.mitre_tactic).filter(Boolean))];
      doc.text(tactics.length ? `Tactics Observed: ${tactics.join(', ')}` : 'No MITRE tactics observed.', 20, y);
      y += 12;

      doc.setTextColor(239, 68, 68);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('Indicator of Compromise (IOC) Summary', 20, y);
      y += 8;
      doc.setTextColor(200, 200, 200);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      const iocs = alerts.filter(a => a.ioc_hit).map(a => a.ioc_value);
      doc.text(iocs.length ? `Matched IOCs: ${iocs.join(', ')}` : 'No IOC matches in this session.', 20, y);
      y += 12;

      doc.setTextColor(239, 68, 68);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('Evidence Statistics', 20, y);
      y += 8;
      doc.setTextColor(200, 200, 200);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      const totalEvidence = alerts.reduce((acc, a) => acc + (a.evidence_packets || 1), 0);
      doc.text(`Total Evidence Packets Correlated: ${totalEvidence}`, 20, y);
      y += 15;

      doc.addPage();
      y = 20;

      doc.setTextColor(239, 68, 68);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('Detection Table', 20, y);
      y += 10;

      if (alerts.length === 0) {
        doc.setTextColor(139, 148, 158);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        doc.text('No alerts detected during this capture session.', 20, y);
        y += 8;
      } else {
        doc.setFillColor(20, 30, 50);
        doc.rect(10, y, 190, 7, 'F');
        doc.setTextColor(139, 148, 158);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text('Detection', 12, y + 5);
        doc.text('Score', 65, y + 5);
        doc.text('Sev', 80, y + 5);
        doc.text('Technique', 95, y + 5);
        doc.text('Evid', 130, y + 5);
        doc.text('Conf%', 145, y + 5);
        doc.text('IOC', 165, y + 5);
        y += 9;

        alerts.slice(0, 35).forEach((a, i) => {
          if (y > 270) {
            doc.addPage();
            y = 20;
          }
          doc.setFillColor(i % 2 === 0 ? 8 : 12, i % 2 === 0 ? 16 : 22, i % 2 === 0 ? 32 : 42);
          doc.rect(10, y, 190, 7, 'F');
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7.5);
          const color = a.risk_level === 'CRITICAL' || a.severity === 'Critical' ? [239, 68, 68] : [249, 115, 22];
          doc.setTextColor(200, 200, 200);
          doc.text(a.category.slice(0, 30), 12, y + 5);
          doc.setTextColor(...color as [number, number, number]);
          doc.text(String(a.threat_score || 0), 65, y + 5);
          doc.text(a.severity, 80, y + 5);
          doc.setTextColor(96, 165, 250);
          doc.text((a.mitre_technique || '—').slice(0, 15), 95, y + 5);
          doc.setTextColor(167, 139, 250);
          doc.text(String(a.evidence_packets || 1), 130, y + 5);
          doc.setTextColor(248, 113, 113);
          doc.text(a.confidence !== undefined ? `${a.confidence}%` : '—', 145, y + 5);
          doc.setTextColor(200, 200, 200);
          doc.text(a.ioc_hit ? 'TRUE' : 'FALSE', 165, y + 5);
          y += 7;
        });
        if (alerts.length > 35) {
          doc.setTextColor(100, 100, 100);
          doc.setFontSize(8);
          doc.text(`... and ${alerts.length - 35} more alerts.`, 12, y + 6);
          y += 10;
        }
      }

      doc.setFillColor(6, 12, 20);
      doc.rect(0, 280, 210, 17, 'F');
      doc.setTextColor(56, 139, 253);
      doc.setFontSize(8);
      doc.text('HexSniff — Enterprise Network Packet Analyzer | Confidential Security Report', 20, 290);

      const pdfBlob = doc.output('blob');
      triggerDownload(`hexsniff-report-${Date.now()}.pdf`, pdfBlob);
    } catch (e) { console.error(e); }
    setExporting(null);
  };

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.32, 0.72, 0, 1] }}
      className="flex flex-col gap-6 max-w-[1800px] mx-auto pb-10"
    >
      {/* ── 3D Hero Section ── */}
      <div className="relative w-full h-[250px] bg-void rounded-2xl border border-border-dim shadow-card overflow-hidden flex flex-col justify-center px-10">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,229,255,0.05)_0%,transparent_70%)] pointer-events-none" />
        <CryptoDiskCanvas />
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <Share2 size={24} className="text-neon-blue" />
            <h1 className="text-2xl font-bold text-white tracking-wide">Reporting & Export System</h1>
          </div>
          <p className="text-sm font-sans text-text-muted max-w-lg">
            Generate cryptographically secure forensic exports of telemetry data, alerts, and executive summaries.
          </p>
        </div>
      </div>

      {/* ── KPIs ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Packets', val: totalPackets, color: 'text-blue-400' },
          { label: 'Total Alerts', val: alerts.length, color: 'text-crimson' },
          { label: 'High Severity', val: alerts.filter(a => a.severity === 'High').length, color: 'text-orange-500' },
          { label: 'Badges Earned', val: achievements.length, color: 'text-purple-400' },
        ].map(({ label, val, color }) => (
          <div key={label} className="glass-panel p-5 rounded-xl flex items-center gap-5">
            <div className={`w-12 h-12 rounded-full border border-border-dim bg-white/5 flex items-center justify-center shrink-0`}>
              <FileText size={20} className={color} />
            </div>
            <div>
              <div className="text-xs font-sans text-text-muted mb-1 uppercase tracking-widest">{label}</div>
              <div className="text-2xl font-mono font-medium tracking-tight text-white">{val}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Export Center */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card lg:col-span-2">
          <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
            <Download size={14} className="text-neon-blue" /> Export Data Interfaces
          </div>
          <div className="p-5 flex flex-col gap-4">
            {[
              { id: 'pcap', label: 'Raw Wireshark PCAP', desc: 'Standard packet capture trace file in binary format. Export capture sessions to review raw bytes, payloads, and protocols inside Wireshark.', color: 'purple', action: exportPCAP },
              { id: 'pdf', label: 'PDF Security Report', desc: 'Professional report with summary, alerts table, and statistics. Ideal for presentations and management briefings.', color: 'red', action: exportPDF },
              { id: 'csv', label: 'CSV Packet Log', desc: 'All captured alerts in CSV format. Import into Excel, Splunk, or any SIEM for further analysis.', color: 'green', action: exportCSV },
              { id: 'json', label: 'JSON Full Dump', desc: 'Complete JSON export of packets, alerts, and metadata. Machine-readable for automated processing and APIs.', color: 'blue', action: exportJSON },
            ].map(({ id, label, desc, color, action }) => (
              <div 
                key={id} 
                className="group p-5 rounded-xl border border-border-dim bg-black/20 hover:bg-white/[0.03] transition-all flex items-center justify-between cursor-pointer"
              >
                <div>
                  <div className="text-sm font-bold text-white mb-1 group-hover:text-neon-blue transition-colors">{label}</div>
                  <div className="text-xs text-text-muted leading-relaxed max-w-xl">{desc}</div>
                </div>
                <button 
                  className={`px-4 py-2 rounded flex items-center gap-2 text-xs font-bold uppercase tracking-widest border transition-all shrink-0 ml-4
                    ${exporting === id ? 'opacity-50 cursor-not-allowed' : ''}
                    ${color === 'purple' ? 'border-purple-500/30 text-purple-400 hover:bg-purple-500/10' : 
                      color === 'red' ? 'border-crimson/30 text-crimson hover:bg-crimson/10' : 
                      color === 'green' ? 'border-green-400/30 text-green-400 hover:bg-green-400/10' : 
                      'border-neon-blue/30 text-neon-blue hover:bg-neon-blue/10'
                    }`}
                  onClick={action} 
                  disabled={exporting === id}
                >
                  {exporting === id ? <Activity size={14} className="animate-spin" /> : <Download size={14} />}
                  {exporting === id ? 'Exporting...' : 'Export'}
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Achievements */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
          <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02]">
            <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
              <Trophy size={14} className="text-neon-blue" /> User Achievements
            </div>
            <span className="text-[10px] text-text-muted font-mono">{achievements.length}/{ACHIEVEMENTS.length} EARNED</span>
          </div>
          <div className="p-5 grid grid-cols-2 gap-3">
            {ACHIEVEMENTS.map(badge => {
              const earned = achievements.includes(badge.id);
              return (
                <div 
                  key={badge.id} 
                  className={`p-3 rounded-lg border flex flex-col items-center justify-center text-center gap-2 transition-all
                    ${earned ? 'border-neon-blue/30 bg-neon-blue/5 shadow-glow-blue' : 'border-white/5 bg-black/20 opacity-40 grayscale'}
                  `}
                  title={badge.desc}
                >
                  <div className="text-2xl">{badge.icon}</div>
                  <div className={`text-xs font-bold ${earned ? 'text-white' : 'text-text-muted'}`}>{badge.name}</div>
                  <div className={`text-[9px] ${earned ? 'text-neon-blue' : 'text-text-muted'}`}>
                    {earned ? '✓ UNLOCKED' : 'LOCKED'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Executive Summary Preview */}
      <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
        <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
          <Shield size={14} className="text-neon-blue" /> Executive Summary Preview
        </div>
        <div className="p-6">
          <div className="p-6 rounded-xl border border-border-dim bg-black/20">
            <div className="text-lg font-bold text-neon-blue mb-1">HexSniff Network Security Report</div>
            <div className="text-xs text-text-muted font-mono mb-6">{new Date().toLocaleString()}</div>

            <div className="text-sm text-text-secondary leading-relaxed space-y-4 max-w-4xl">
              <p>This report summarizes the findings from the HexSniff network packet analysis session. A total of <strong className="text-white font-mono">{totalPackets.toLocaleString()} packets</strong> were captured and analyzed.</p>
              
              <p>The IDS engine detected <strong className={`font-mono ${alerts.length > 0 ? 'text-crimson' : 'text-green-400'}`}>{alerts.length} security events</strong>, of which <span className="text-white">{alerts.filter(a => a.severity === 'High').length}</span> were classified as High severity.</p>
              
              <div className="flex gap-4 text-xs font-mono bg-white/5 p-3 rounded w-fit border border-white/10">
                <span>TCP: {protocolCounts['TCP'] || 0}</span>
                <span>UDP: {protocolCounts['UDP'] || 0}</span>
                <span>DNS: {protocolCounts['DNS'] || 0}</span>
                <span>ICMP: {protocolCounts['ICMP'] || 0}</span>
                <span>ARP: {protocolCounts['ARP'] || 0}</span>
              </div>
              
              {alerts.length > 0 && (
                <div className="p-4 rounded-lg bg-orange-500/10 border border-orange-500/30 text-orange-400 flex gap-3 mt-4">
                  <Activity size={18} className="shrink-0" />
                  <div>
                    <strong>Evidence-based action required:</strong> Investigate the following detected MITRE techniques: 
                    <span className="text-white ml-2">
                      {[...new Set(alerts.map(a => `${a.mitre_technique} (${a.mitre_tactic || 'Unmapped Tactic'})`).filter(Boolean))].join(', ') || 'Unmapped anomalies'}
                    </span>. 
                    <br/>Max confidence across all alerts: {Math.max(...alerts.map(a => a.confidence || 0))}%.
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </m.div>
  );
}
