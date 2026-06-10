import { useLocation } from 'react-router-dom';
import { Activity, ServerCrash } from 'lucide-react';
import { useStore } from '../../store';
import { m, AnimatePresence } from 'framer-motion';

const PAGE_TITLES: Record<string, string> = {
  '/': 'SOC Command Center',
  '/analyzer': 'Packet Analyzer',
  '/map': 'Global Threat Map',
  '/ai': 'AI Security Analyst',
  '/topology': 'Network Topology',
  '/analytics': 'Protocol Analytics',
  '/intel': 'Threat Intelligence',
  '/investigate': 'Investigation Workspace',
  '/validation': 'Detection Validation Lab',
  '/engineering': 'Detection Engineering',
  '/reports': 'Reports & Export',
};

export function TopBar() {
  const { mode, backendError, packetRate, totalPackets, alerts } = useStore();
  const location = useLocation();
  const title = PAGE_TITLES[location.pathname] || 'HexSniff';

  const criticalCount = alerts.filter(a => a.severity === 'Critical').length;
  const isHighAlert = criticalCount > 0;

  return (
    <m.div 
      initial={{ y: -50, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className={`h-[72px] shrink-0 flex items-center px-8 gap-6 border-b transition-colors duration-500 z-40 ${
      isHighAlert ? 'bg-crimson/5 border-crimson/30 shadow-[inset_0_10px_30px_rgba(255,42,85,0.05)]' : 'bg-surface-active/50 border-border-dim backdrop-blur-2xl'
    }`}
    >
      
      {/* Title / Breadcrumb */}
      <div className="flex items-center gap-3 text-sm">
        <span className="text-text-muted font-mono tracking-[0.2em] text-[10px] uppercase">HexSniff</span>
        <span className="text-border-subtle">/</span>
        <AnimatePresence mode="wait">
          <m.span 
            key={title}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 10 }}
            transition={{ duration: 0.3 }}
            className={`font-sans font-bold tracking-widest uppercase text-xs ${isHighAlert ? 'text-crimson text-glow-red' : 'text-white'}`}
          >
            {title}
          </m.span>
        </AnimatePresence>
      </div>

      <div className="flex-1" />

      {/* Global Threat Status Indicator */}
      <div className="hidden md:flex items-center gap-2 px-5 py-2 rounded-xl bg-void/50 border border-border-dim shadow-inner">
        <Activity size={14} className={isHighAlert ? 'text-crimson drop-shadow-[0_0_8px_rgba(255,42,85,0.8)]' : 'text-neon-blue drop-shadow-[0_0_8px_rgba(0,240,255,0.8)]'} />
        <span className="text-[10px] font-mono uppercase tracking-widest text-text-muted">
          Threat Level: <span className={isHighAlert ? 'text-crimson font-bold text-glow-red' : 'text-neon-blue text-glow-blue'}>{isHighAlert ? 'CRITICAL' : 'NOMINAL'}</span>
        </span>
      </div>

      {backendError && (
        <div className="flex items-center gap-2 text-crimson text-xs px-4 py-2 bg-crimson/10 border border-crimson/30 rounded-xl shadow-glow-red animate-pulse">
          <ServerCrash size={14} />
          <span className="truncate max-w-[200px] font-bold tracking-wider">{backendError}</span>
        </div>
      )}

      {/* Metrics */}
      <div className="flex items-center gap-4 text-xs font-mono text-text-muted">
        {totalPackets > 0 && <span>{totalPackets.toLocaleString()} pkts</span>}
        {packetRate > 0 && <span className="text-white text-glow-blue font-bold">{packetRate} pps</span>}
      </div>

      {/* Status Pill */}
      <div className={`flex items-center gap-2 px-4 py-2 rounded-xl text-[10px] font-bold uppercase tracking-widest border transition-all ${
        mode === 'live' ? 'text-neon-blue border-neon-blue/50 bg-neon-blue/10 shadow-glow-blue' : 
        mode === 'replay' ? 'text-amber border-amber/50 bg-amber/10 shadow-glow-amber' : 
        'text-text-muted border-border-dim bg-white/5'
      }`}>
        <span className={`w-1.5 h-1.5 rounded-full ${mode === 'live' ? 'bg-neon-blue animate-pulse shadow-[0_0_8px_rgba(0,240,255,1)]' : mode === 'replay' ? 'bg-amber shadow-[0_0_8px_rgba(255,179,0,1)]' : 'bg-current'}`} />
        {mode === 'live' ? 'Live' : mode === 'replay' ? 'Sim' : 'Idle'}
      </div>

    </m.div>
  );
}
