import { useEffect, useRef } from 'react';
import { BarChart3, Activity, Zap, Database, Network } from 'lucide-react';
import { useStore } from '../store';
import {
  Chart as ChartJS, ArcElement, CategoryScale, LinearScale,
  BarElement, PointElement, LineElement, Filler, Tooltip, Legend,
  type ChartOptions
} from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';
import { m } from 'framer-motion';

ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler, Tooltip, Legend);

const PIE_COLORS = ['#388bfd', '#10b981', '#8b5cf6', '#ec4899', '#f59e0b', '#6b7280'];

// ── 3D Data Vortex Animation ──
function DataVortex() {
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

    const particles: any[] = [];
    const numRings = 15;
    const ptsPerRing = 30;

    for (let r = 0; r < numRings; r++) {
      for (let p = 0; p < ptsPerRing; p++) {
        const angle = (p / ptsPerRing) * Math.PI * 2;
        particles.push({
          angle,
          radius: 120, // Base cylinder radius
          z: (r / numRings) * 800 - 400, // Spread along Z axis
          speed: 2 + Math.random() * 3,
          isData: Math.random() > 0.8
        });
      }
    }

    const render = () => {
      time += 0.01;
      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;

      // Rotate camera
      const rotX = Math.sin(time * 0.5) * 0.2;
      const rotY = time * 0.2;

      const projected = particles.map(p => {
        // Move forward
        p.z -= p.speed;
        if (p.z < -400) {
          p.z = 400;
          p.isData = Math.random() > 0.8;
        }

        let x = Math.cos(p.angle) * p.radius;
        let y = Math.sin(p.angle) * p.radius;
        let z = p.z;

        // Apply twist
        const twist = z * 0.005 * Math.sin(time);
        const tx = x * Math.cos(twist) - y * Math.sin(twist);
        const ty = x * Math.sin(twist) + y * Math.cos(twist);
        x = tx; y = ty;

        // Rotate X
        let y1 = y * Math.cos(rotX) - z * Math.sin(rotX);
        let z1 = y * Math.sin(rotX) + z * Math.cos(rotX);
        // Rotate Y
        let x2 = x * Math.cos(rotY) + z1 * Math.sin(rotY);
        let z2 = -x * Math.sin(rotY) + z1 * Math.cos(rotY);

        return { ...p, x: cx + x2, y: cy + y1, z: z2 };
      });

      projected.sort((a, b) => b.z - a.z);

      projected.forEach(p => {
        const scale = 400 / (400 + p.z);
        if (scale < 0) return;

        const alpha = Math.min(1, Math.max(0, (p.z + 400) / 800));
        
        ctx.beginPath();
        if (p.isData) {
          ctx.arc(p.x, p.y, 2 * scale, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(0, 229, 255, ${alpha})`;
          ctx.shadowBlur = 8;
          ctx.shadowColor = '#00E5FF';
        } else {
          ctx.arc(p.x, p.y, 0.5 * scale, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(255, 255, 255, ${alpha * 0.3})`;
          ctx.shadowBlur = 0;
        }
        ctx.fill();
        ctx.shadowBlur = 0;
      });

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

export function ProtocolAnalytics() {
  const { packets, protocolCounts, alerts, timelineLabels, timelineCounts } = useStore();

  const total = Object.values(protocolCounts).reduce((a, b) => a + b, 0) || 1;

  // Protocol doughnut
  const protoLabels = ['TCP', 'UDP', 'DNS', 'ICMP', 'ARP', 'Other'];
  const protoDoughnut = {
    labels: protoLabels,
    datasets: [{ data: protoLabels.map(l => protocolCounts[l] || 0), backgroundColor: PIE_COLORS.map(c => c + '99'), borderColor: PIE_COLORS, borderWidth: 1.5 }],
  };

  const doughnutOpts: ChartOptions<'doughnut'> = {
    responsive: true, maintainAspectRatio: false,
    cutout: '70%',
    plugins: { legend: { position: 'right', labels: { color: '#8b949e', font: { size: 11, family: 'monospace' }, padding: 16 } } },
    animation: { duration: 1000, easing: 'easeOutQuart' },
    elements: { arc: { borderJoinStyle: 'round' } }
  };

  // Alert category bar
  const alertCats = ['SYN Flood DDoS', 'Port Scanning', 'Credential Leak', 'SQL Injection', 'Path Traversal'];
  const alertBar = {
    labels: alertCats.map(c => c.replace(' ', '\n')),
    datasets: [{
      label: 'Incidents',
      data: alertCats.map(cat => alerts.filter(a => a.category === cat).length),
      backgroundColor: ['rgba(255,42,85,0.7)', 'rgba(249,115,22,0.7)', 'rgba(234,179,8,0.7)', 'rgba(255,42,85,0.7)', 'rgba(139,92,246,0.7)'],
      borderColor: ['#FF2A55', '#f97316', '#eab308', '#FF2A55', '#8b5cf6'],
      borderWidth: 1,
      borderRadius: 4,
    }],
  };

  const barOpts: ChartOptions<'bar'> = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#8b949e', font: { size: 10, family: 'monospace' } }, grid: { color: 'rgba(255,255,255,0.02)' } },
      y: { ticks: { color: '#8b949e', font: { size: 10, family: 'monospace' } }, grid: { color: 'rgba(255,255,255,0.02)' }, beginAtZero: true },
    },
    animation: { duration: 1000, easing: 'easeOutQuart' },
  };

  // Traffic timeline
  const timelineData = {
    labels: timelineLabels,
    datasets: [{
      label: 'Packets/s',
      fill: true,
      data: timelineCounts,
      borderColor: '#00E5FF',
      backgroundColor: 'rgba(0, 229, 255, 0.05)',
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4,
      tension: 0.4,
    }],
  };

  const lineOpts: ChartOptions<'line'> = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
    scales: {
      x: { ticks: { color: '#8b949e', font: { size: 9, family: 'monospace' }, maxTicksLimit: 8 }, grid: { color: 'rgba(255,255,255,0.02)' } },
      y: { ticks: { color: '#8b949e', font: { size: 10, family: 'monospace' } }, grid: { color: 'rgba(255,255,255,0.02)' }, beginAtZero: true },
    },
    animation: false,
    interaction: { mode: 'nearest', axis: 'x', intersect: false }
  };

  // DNS top queries
  const dnsPackets = packets.filter(p => p.dns_query);
  const dnsCounts: Record<string, number> = {};
  dnsPackets.forEach(p => { if (p.dns_query) dnsCounts[p.dns_query] = (dnsCounts[p.dns_query] || 0) + 1; });
  const topDns = Object.entries(dnsCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);

  // Port distribution
  const portCounts: Record<number, number> = {};
  packets.forEach(p => { if (p.dst_port) portCounts[p.dst_port] = (portCounts[p.dst_port] || 0) + 1; });
  const topPorts = Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);

  const portNames: Record<number, string> = { 80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 53: 'DNS', 8080: 'ALT-HTTP', 3306: 'MySQL', 3389: 'RDP', 25: 'SMTP' };

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.32, 0.72, 0, 1] }}
      className="flex flex-col gap-6 max-w-[1800px] mx-auto pb-10"
    >
      {/* ── 3D Hero Section ── */}
      <div className="relative w-full h-[250px] bg-void rounded-2xl border border-border-dim shadow-card overflow-hidden flex flex-col justify-center px-10">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,229,255,0.08)_0%,transparent_70%)] pointer-events-none" />
        <DataVortex />
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <Activity size={24} className="text-neon-blue" />
            <h1 className="text-2xl font-bold text-white tracking-wide">Protocol Analytics</h1>
          </div>
          <p className="text-sm font-sans text-text-muted max-w-lg">
            High-velocity telemetry analysis. Monitoring protocol distribution, top talkers, and anomalous DNS requests in real-time.
          </p>
        </div>
      </div>

      {/* ── Summary Stats ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {protoLabels.slice(0, 4).map((proto, i) => (
          <m.div 
            key={proto}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: i * 0.1 }}
            className="glass-panel p-5 rounded-xl flex items-center gap-5"
          >
            <div className={`w-12 h-12 rounded-full border border-border-dim bg-white/5 flex items-center justify-center shrink-0`}>
              <BarChart3 size={20} className={['text-blue-500', 'text-green-500', 'text-purple-500', 'text-pink-500'][i]} />
            </div>
            <div>
              <div className="text-xs font-sans text-text-muted mb-1">{proto} TRACE</div>
              <div className="flex items-baseline gap-2">
                <div className="text-2xl font-mono font-medium tracking-tight text-white">{protocolCounts[proto] || 0}</div>
                <div className="text-[10px] text-neon-blue">{total > 0 ? `${((protocolCounts[proto] || 0) / total * 100).toFixed(1)}%` : '0%'}</div>
              </div>
            </div>
          </m.div>
        ))}
      </div>

      {/* ── Main Charts Grid ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Protocol Distribution */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
          <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
            <Database size={14} className="text-neon-blue" /> Protocol Distribution
          </div>
          <div className="p-5 h-[300px]">
            <Doughnut data={protoDoughnut} options={doughnutOpts} />
          </div>
        </div>

        {/* Alert Categories */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
          <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
            <Zap size={14} className="text-crimson" /> Incident Vector Breakdown
          </div>
          <div className="p-5 h-[300px]">
            <Bar data={alertBar} options={barOpts} />
          </div>
        </div>

      </div>

      {/* ── Traffic Timeline ── */}
      <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
        <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02]">
          <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
            <Activity size={14} className="text-neon-blue" /> Traffic Rate Timeline
          </div>
        </div>
        <div className="p-5 h-[250px]">
          <Line data={timelineData} options={lineOpts} />
        </div>
      </div>

      {/* ── Lower Tables Grid ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Top DNS */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
          <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02]">
            <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
              <Network size={14} className="text-neon-blue" /> Top DNS Queries
            </div>
            <span className="text-[10px] text-text-muted">{topDns.length} unique domains</span>
          </div>
          <div className="p-0 overflow-x-auto min-h-[200px]">
            {topDns.length === 0 ? (
              <div className="p-10 text-center text-sm text-text-muted">No DNS traffic captured</div>
            ) : (
              <table className="w-full text-left border-collapse whitespace-nowrap">
                <thead>
                  <tr className="bg-white/[0.01] text-[10px] uppercase tracking-wider text-text-muted border-b border-border-dim font-mono">
                    <th className="py-3 px-5 font-medium">Domain</th>
                    <th className="py-3 px-5 font-medium text-right">Hit Count</th>
                  </tr>
                </thead>
                <tbody className="font-mono text-xs">
                  {topDns.map(([domain, count]) => (
                    <tr key={domain} className="border-b border-border-dim/30 hover:bg-white/5 transition-colors">
                      <td className="py-3 px-5 text-neon-blue">{domain}</td>
                      <td className="py-3 px-5 text-right text-white">{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Top Ports */}
        <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
          <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
            <Database size={14} className="text-neon-blue" /> Top Destination Ports
          </div>
          <div className="p-5 flex flex-col gap-4">
            {topPorts.length === 0 ? (
              <div className="text-center text-sm text-text-muted py-6">No port data</div>
            ) : topPorts.map(([port, count]) => {
              const pct = Math.round((Number(count) / (Number(topPorts[0][1]) || 1)) * 100);
              return (
                <div key={port} className="group">
                  <div className="flex justify-between text-xs mb-2">
                    <span className="font-mono text-neon-blue">
                      :{port} <span className="text-text-muted ml-2 font-sans">{portNames[Number(port)] || 'UNKNOWN'}</span>
                    </span>
                    <span className="font-mono text-white">{count} PKT</span>
                  </div>
                  <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                    <m.div 
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 1, ease: [0.32, 0.72, 0, 1] }}
                      className="h-full bg-neon-blue rounded-full shadow-glow-blue"
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>
    </m.div>
  );
}
