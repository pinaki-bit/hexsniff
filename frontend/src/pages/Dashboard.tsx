import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Activity, Globe2,
  Network, Cpu, TrendingUp,
  ShieldAlert, Zap, Database, Brain
} from 'lucide-react';
import { useStore, store } from '../store';
import { m, AnimatePresence } from 'framer-motion';
import { ThreatGlobe } from '../components/Visuals/ThreatGlobe';

// ── Health Score calculator
function calcHealthScore(alerts: any[], _packets: any[], _protoCounts: Record<string, number>): number {
  let score = 100;
  const highAlerts = alerts.filter(a => a.severity === 'High' || a.severity === 'Critical').length;
  const synFloods = alerts.filter(a => a.category === 'SYN Flood DDoS').length;
  const scans = alerts.filter(a => a.category === 'Port Scanning').length;
  score -= Math.min(highAlerts * 4, 40);
  score -= Math.min(synFloods * 8, 24);
  score -= Math.min(scans * 3, 15);
  return Math.max(score, 0);
}

// ── Animated Counter
function AnimCounter({ target, suffix = '' }: { target: number; suffix?: string }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let frame: number;
    const start = performance.now();
    const dur = 800;
    const animate = (now: number) => {
      const t = Math.min((now - start) / dur, 1);
      const ease = 1 - Math.pow(1 - t, 4);
      setVal(Math.round(ease * target));
      if (t < 1) frame = requestAnimationFrame(animate);
    };
    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [target]);
  return <span>{val.toLocaleString()}{suffix}</span>;
}

// ── Data Telemetry Background
function TelemetryStream({ isHighAlert }: { isHighAlert: boolean }) {
  const streams = Array.from({ length: 20 }); // 20 columns
  return (
    <div className="absolute inset-0 overflow-hidden opacity-20 pointer-events-none flex justify-between px-4" style={{ perspective: '1000px' }}>
      {streams.map((_, i) => (
        <m.div
          key={i}
          initial={{ y: -800 }}
          animate={{ y: 800 }}
          transition={{
            duration: Math.random() * 10 + 10,
            repeat: Infinity,
            ease: "linear",
            delay: Math.random() * -10
          }}
          className={`font-mono text-[10px] leading-relaxed break-all w-8 text-center mix-blend-screen ${isHighAlert ? 'text-crimson' : 'text-neon-blue'}`}
          style={{ opacity: Math.random() * 0.5 + 0.1, filter: 'blur(0.5px)' }}
        >
          {Array.from({ length: 30 }).map(() => Math.random().toString(16).substring(2, 10).toUpperCase()).join('\n')}
        </m.div>
      ))}
    </div>
  );
}

// ── Robot Assembly Sequence
function DashboardAssembly({ onComplete }: { onComplete: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onComplete, 3500);
    return () => clearTimeout(timer);
  }, []); // Removed onComplete to prevent infinite loading loop when store updates

  return (
    <m.div 
      key="assembly"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, scale: 1.2, filter: "blur(10px)" }}
      transition={{ duration: 0.8, ease: "easeInOut" }}
      className="flex flex-col items-center justify-center min-h-[70vh] w-full"
    >
      <m.div className="relative flex flex-col items-center">
        <m.svg
          width="240"
          height="240"
          viewBox="0 0 200 200"
          className="text-neon-blue drop-shadow-[0_0_20px_rgba(0,240,255,0.6)]"
        >
          {/* Outer Hexagon Shell */}
          <m.polygon
            points="100,10 180,50 180,150 100,190 20,150 20,50"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 1 }}
            transition={{ duration: 1.5, ease: "easeInOut" }}
          />
          {/* Inner Structural Crosshairs */}
          <m.path
            d="M 100 15 L 100 185 M 25 100 L 175 100 M 40 40 L 160 160 M 40 160 L 160 40"
            fill="none"
            stroke="currentColor"
            strokeWidth="1"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 0.4 }}
            transition={{ duration: 1, delay: 0.8, ease: "circOut" }}
          />
          {/* Central AI Core */}
          <m.circle
            cx="100" cy="100" r="25"
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.8, delay: 1.5, type: "spring", stiffness: 200 }}
          />
          {/* Rotating Scanner Ring */}
          <m.circle
            cx="100" cy="100" r="60"
            fill="none"
            stroke="currentColor"
            strokeWidth="1"
            strokeDasharray="4 12"
            initial={{ rotate: 0, opacity: 0 }}
            animate={{ rotate: 360, opacity: 0.8 }}
            transition={{ rotate: { duration: 8, repeat: Infinity, ease: "linear" }, opacity: { duration: 1, delay: 1.2 } }}
            style={{ transformOrigin: "center" }}
          />
          {/* Data Nodes */}
          {[
            { cx: 100, cy: 10 }, { cx: 180, cy: 50 }, { cx: 180, cy: 150 },
            { cx: 100, cy: 190 }, { cx: 20, cy: 150 }, { cx: 20, cy: 50 }
          ].map((pos, i) => (
            <m.circle
              key={i}
              cx={pos.cx} cy={pos.cy} r="4"
              fill="currentColor"
              initial={{ scale: 0 }}
              animate={{ scale: [0, 1.5, 1] }}
              transition={{ duration: 0.5, delay: 1.5 + i * 0.1 }}
            />
          ))}
        </m.svg>

        <m.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.8, duration: 0.5 }}
          className="mt-12 flex flex-col items-center gap-3"
        >
          <div className="text-neon-blue font-bold tracking-[0.4em] text-xs uppercase text-glow-blue">
            Constructing Aegis Interface
          </div>
          <div className="w-64 h-[2px] bg-void border border-white/10 overflow-hidden relative">
            <m.div 
              initial={{ width: 0 }}
              animate={{ width: "100%" }}
              transition={{ duration: 3, ease: "easeInOut" }}
              className="absolute inset-y-0 left-0 bg-neon-blue shadow-glow-blue"
            />
          </div>
        </m.div>
      </m.div>
    </m.div>
  );
}

// ── Main Dashboard Page
export function Dashboard() {
  const navigate = useNavigate();
  const [isAssembling, setIsAssembling] = useState(true);
  const {
    packets, alerts, totalPackets,
    dataRate, protocolCounts
  } = useStore();

  const score = calcHealthScore(alerts, packets, protocolCounts);
  const highAlerts = alerts.filter(a => a.severity === 'High' || a.severity === 'Critical');
  const isHighAlert = highAlerts.length > 0;
  const recentPackets = packets.slice(-10).reverse();

  // Top talkers
  const talkers: Record<string, number> = {};
  packets.forEach(p => { talkers[p.src_ip] = (talkers[p.src_ip] || 0) + 1; });
  const topTalkers = Object.entries(talkers).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="w-full h-full">
      <AnimatePresence mode="wait">
        {isAssembling ? (
          <DashboardAssembly key="assembly" onComplete={() => setIsAssembling(false)} />
        ) : (
          <m.div 
            key="dashboard"
            initial={{ opacity: 0, scale: 0.98, filter: "blur(10px)" }}
            animate={{ opacity: 1, scale: 1, filter: "blur(0px)" }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.8, ease: "easeOut" }}
            className="flex flex-col gap-6 max-w-[1800px] mx-auto pb-10"
          >
      {/* ── 1M DOLLAR HERO SECTION ── */}
      <m.div 
        initial={{ scale: 0.98, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        className="relative w-full h-[380px] bg-void flex items-center justify-center overflow-hidden rounded-3xl border border-border-dim shadow-[0_0_50px_rgba(0,0,0,0.8)] group"
      >
        {/* Animated Cyber Grid Background */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:40px_40px] [mask-image:radial-gradient(ellipse_60%_60%_at_50%_50%,#000_20%,transparent_100%)] opacity-30 pointer-events-none" />
        
        {/* Falling Raw Data Telemetry Stream */}
        <TelemetryStream isHighAlert={isHighAlert} />
        
        {/* Sweeping Laser Scanline */}
        <m.div 
          animate={{ y: ['-10%', '110%'] }}
          transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
          className={`absolute left-0 right-0 h-[2px] opacity-40 pointer-events-none z-10 ${isHighAlert ? 'bg-crimson shadow-[0_0_20px_#FF2A55]' : 'bg-neon-blue shadow-[0_0_20px_#00F0FF]'}`}
        />

        {/* Dynamic Pulse Glow */}
        <m.div 
          animate={{ opacity: [0.3, 0.6, 0.3], scale: [1, 1.05, 1] }}
          transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
          className={`absolute inset-0 pointer-events-none ${isHighAlert ? 'bg-[radial-gradient(ellipse_at_center,rgba(255,42,85,0.15)_0%,transparent_60%)]' : 'bg-[radial-gradient(ellipse_at_center,rgba(0,240,255,0.1)_0%,transparent_60%)]'}`} 
        />
        
        {/* React Three Fiber Globe Component */}
        <ThreatGlobe isHighAlert={isHighAlert} packets={packets} />
        
        {/* High-End Glass HUD Overlays - Top Left */}
        <m.div 
          initial={{ x: -50, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: 0.5, duration: 0.6, type: "spring", stiffness: 100 }}
          className="absolute top-8 left-8 flex flex-col gap-2 pointer-events-none z-20"
        >
          <div className="flex items-center gap-3 mb-1">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center backdrop-blur-xl border ${isHighAlert ? 'bg-crimson/10 border-crimson/30 shadow-glow-red' : 'bg-neon-blue/10 border-neon-blue/30 shadow-glow-blue'}`}>
              <Activity size={18} className={isHighAlert ? 'text-crimson animate-pulse' : 'text-neon-blue'} />
            </div>
            <div>
              <span className="text-xs font-mono tracking-[0.3em] uppercase text-white font-black drop-shadow-md">Aegis Matrix</span>
              <div className={`text-[9px] font-mono tracking-widest uppercase ${isHighAlert ? 'text-crimson' : 'text-neon-blue'}`}>Live Telemetry</div>
            </div>
          </div>
          <div className="text-xs font-sans text-text-muted bg-black/40 backdrop-blur-md px-4 py-2 rounded-lg border border-white/5 shadow-modal">
            Tracking <span className="text-white font-bold">{packets.length}</span> active connections
          </div>
        </m.div>
        
        {/* High-End Glass HUD Overlays - Bottom Right */}
        <m.div 
          initial={{ x: 50, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: 0.7, duration: 0.6, type: "spring", stiffness: 100 }}
          className="absolute bottom-8 right-8 flex flex-col items-end gap-2 pointer-events-none z-20"
        >
          <div className="flex items-center gap-2 bg-black/40 backdrop-blur-xl px-3 py-1.5 rounded-t-lg border-b-2 border-transparent border-b-white/10">
             <div className={`w-2 h-2 rounded-full animate-pulse ${isHighAlert ? 'bg-crimson shadow-glow-red' : 'bg-neon-blue shadow-glow-blue'}`} />
             <span className="text-[10px] font-mono tracking-widest text-text-muted uppercase">System Status</span>
          </div>
          <div className={`px-6 py-2 rounded-xl border text-sm font-black tracking-widest uppercase backdrop-blur-2xl shadow-modal flex items-center gap-2 ${isHighAlert ? 'bg-crimson/20 border-crimson/50 text-crimson shadow-glow-red' : 'bg-neon-blue/10 border-neon-blue/30 text-neon-blue shadow-[0_0_15px_rgba(0,240,255,0.4)]'}`}>
            {isHighAlert ? (
              <>
                <ShieldAlert size={16} /> Threat Detected
              </>
            ) : (
              <>
                <Shield size={16} /> All Systems Nominal
              </>
            )}
          </div>
        </m.div>

        {/* Framing Corner Accents */}
        <div className={`absolute top-0 left-0 w-16 h-16 border-t-2 border-l-2 opacity-30 ${isHighAlert ? 'border-crimson' : 'border-neon-blue'}`} style={{ borderTopLeftRadius: '24px' }} />
        <div className={`absolute top-0 right-0 w-16 h-16 border-t-2 border-r-2 opacity-30 ${isHighAlert ? 'border-crimson' : 'border-neon-blue'}`} style={{ borderTopRightRadius: '24px' }} />
        <div className={`absolute bottom-0 left-0 w-16 h-16 border-b-2 border-l-2 opacity-30 ${isHighAlert ? 'border-crimson' : 'border-neon-blue'}`} style={{ borderBottomLeftRadius: '24px' }} />
        <div className={`absolute bottom-0 right-0 w-16 h-16 border-b-2 border-r-2 opacity-30 ${isHighAlert ? 'border-crimson' : 'border-neon-blue'}`} style={{ borderBottomRightRadius: '24px' }} />
      </m.div>

      {/* ── KPI Metric Row ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'System Integrity', value: score, suffix: '%', icon: Shield, color: score > 80 ? 'text-emerald text-glow-emerald' : 'text-crimson text-glow-red' },
          { label: 'Packet Volume', value: totalPackets, icon: Database, color: 'text-text-muted' },
          { label: 'Critical Threads', value: highAlerts.length, icon: ShieldAlert, color: isHighAlert ? 'text-crimson text-glow-red' : 'text-text-muted' },
          { label: 'I/O Rate', value: dataRate, suffix: ' KB/s', icon: Activity, color: 'text-white' },
        ].map((kpi, index) => (
          <m.div 
            key={kpi.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: index * 0.1, ease: [0.16, 1, 0.3, 1] }}
            className="glass-panel p-5 rounded-xl flex items-center gap-5 group cursor-pointer"
          >
            <div className={`w-12 h-12 rounded-full border border-border-dim bg-white/5 flex items-center justify-center shrink-0 transition-all duration-500 group-hover:bg-white/10 group-hover:scale-110 ${kpi.color}`}>
              <kpi.icon size={20} />
            </div>
            <div>
              <div className="text-xs font-sans text-text-muted mb-1">{kpi.label}</div>
              <div className={`text-2xl font-mono font-bold tracking-tight ${kpi.color}`}>
                <AnimCounter target={kpi.value} suffix={kpi.suffix} />
              </div>
            </div>
          </m.div>
        ))}
      </div>

      {/* ── Grid Layout ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Live Packet Stream */}
        <div className="glass-panel rounded-xl lg:col-span-2 flex flex-col overflow-hidden shadow-card">
          <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02] backdrop-blur-md sticky top-0 z-10">
            <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
              <Zap size={14} className="text-neon-blue" /> Terminal Data Stream
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-neon-blue animate-pulse shadow-glow-blue" />
              <span className="text-[10px] font-mono tracking-widest uppercase text-text-muted">Live Capture</span>
            </div>
          </div>
          <div className="p-0 overflow-x-auto min-h-[300px]">
            <table className="w-full text-left border-collapse whitespace-nowrap">
              <thead>
                <tr className="bg-surface-hover text-[10px] uppercase tracking-wider text-text-muted border-b border-border-dim font-mono">
                  <th className="py-3 px-5 font-medium">Timestamp</th>
                  <th className="py-3 px-5 font-medium">Protocol</th>
                  <th className="py-3 px-5 font-medium">Source IP</th>
                  <th className="py-3 px-5 font-medium">Destination IP</th>
                  <th className="py-3 px-5 font-medium">Payload Signature</th>
                </tr>
              </thead>
              <tbody className="font-mono text-xs">
                <AnimatePresence initial={false}>
                  {recentPackets.map((p) => (
                    <m.tr 
                      key={p.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.3 }}
                      onClick={() => { store.setSelectedPacket(p); navigate('/analyzer'); }}
                      className={`cursor-pointer border-b border-border-dim/50 transition-colors hover:bg-surface-active ${p.alerts?.length ? 'bg-crimson/5 text-crimson' : 'text-text-muted hover:text-white'}`}
                    >
                      <td className="py-3 px-5">{new Date(p.timestamp * 1000).toISOString().split('T')[1].replace('Z','')}</td>
                      <td className="py-3 px-5">
                        <span className={`px-2 py-1 rounded border text-[10px] ${p.proto === 'TCP' ? 'bg-white/10 border-white/20 text-white' : 'bg-transparent border-border-dim text-text-muted'}`}>
                          {p.proto}
                        </span>
                      </td>
                      <td className="py-3 px-5">{p.src_ip}</td>
                      <td className="py-3 px-5">{p.dst_ip}</td>
                      <td className="py-3 px-5 truncate max-w-[250px]">
                        {p.summary}
                      </td>
                    </m.tr>
                  ))}
                </AnimatePresence>
                {recentPackets.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-16 text-center text-text-muted font-sans text-sm">
                      Awaiting telemetry...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Intelligence Side Column */}
        <div className="flex flex-col gap-6">
          
          {/* Top Talkers */}
          <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
            <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
              <Network size={14} className="text-neon-blue" /> Node Traffic Volume
            </div>
            <div className="p-5 flex flex-col gap-4">
              {topTalkers.length === 0 ? (
                <div className="text-center text-text-muted text-sm py-4">No data available</div>
              ) : topTalkers.map(([ip, count], i) => (
                <div key={ip} className="group cursor-pointer">
                  <div className="flex justify-between text-xs font-mono mb-2">
                    <span className="text-white group-hover:text-neon-blue transition-colors text-glow-blue">{ip}</span>
                    <span className="text-text-muted">{count} PKT</span>
                  </div>
                  <div className="h-1.5 bg-void rounded-full overflow-hidden border border-white/5">
                    <m.div 
                      initial={{ width: 0 }}
                      animate={{ width: `${Math.min((count / topTalkers[0][1]) * 100, 100)}%` }}
                      transition={{ duration: 1.5, ease: [0.16, 1, 0.3, 1] }}
                      className={`h-full rounded-full ${i === 0 ? 'bg-neon-blue shadow-glow-blue' : 'bg-white/30'}`}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="glass-panel rounded-xl flex flex-col overflow-hidden shadow-card">
            <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-sans font-semibold text-white bg-white/[0.02]">
              <Cpu size={14} className="text-neon-blue" /> Execution Modules
            </div>
            <div className="p-4 grid grid-cols-2 gap-3">
              {[
                { label: 'Analyzer', icon: Network, path: '/analyzer' },
                { label: 'Orbit Map', icon: Globe2, path: '/map' },
                { label: 'Overseer AI', icon: Brain, path: '/ai' },
                { label: 'Reports', icon: TrendingUp, path: '/reports' }
              ].map(module => (
                <m.button 
                  key={module.label}
                  whileHover={{ scale: 1.02, y: -2 }} 
                  whileTap={{ scale: 0.98 }} 
                  onClick={() => navigate(module.path)} 
                  className="p-4 rounded-xl bg-surface-hover border border-border-subtle hover:border-border-bright hover:bg-surface-active flex flex-col items-center gap-3 transition-all group"
                >
                  <module.icon size={20} className="text-text-muted group-hover:text-neon-blue group-hover:drop-shadow-[0_0_8px_rgba(0,240,255,0.8)] transition-all" />
                  <span className="text-[10px] font-sans font-bold text-white tracking-wide uppercase">{module.label}</span>
                </m.button>
              ))}
            </div>
          </div>

        </div>
      </div>

          </m.div>
        )}
      </AnimatePresence>
    </div>
  );
}
