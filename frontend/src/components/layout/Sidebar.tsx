import { Link, useLocation } from 'react-router-dom';
import { 
  Activity, Globe, Terminal, Shield, 
  Map, Fingerprint, ActivitySquare, AlertTriangle, PlaySquare,
  FileCode2, ShieldAlert, Server, Target, Database
} from 'lucide-react';
import { useStore } from '../../store';
import { m, AnimatePresence } from 'framer-motion';
import { useState } from 'react';

const NAV_ITEMS = [
  { path: '/', label: 'DASHBOARD', icon: ActivitySquare },
  { path: '/analyzer', label: 'PACKET_MATRIX', icon: Terminal },
  { path: '/map', label: 'THREAT_ORBIT', icon: Map },
  { path: '/ai', label: 'AI_OVERSEER', icon: Shield },
  { path: '/topology', label: 'TOPOLOGY_SCAN', icon: Globe },
  { path: '/analytics', label: 'DATA_TELEM', icon: Activity },
  { path: '/intel', label: 'THREAT_INTEL', icon: ShieldAlert },
  { path: '/assets', label: 'ASSET_INV', icon: Server },
  { path: '/investigate', label: 'FORENSICS', icon: Fingerprint },
  { path: '/hunt', label: 'THREAT_HUNT', icon: Target },
  { path: '/validation', label: 'DETECTION_LAB', icon: PlaySquare },
  { path: '/engineering', label: 'SIG_ENGINE', icon: FileCode2 },
  { path: '/cases', label: 'CASE_MGMT', icon: Database },
  { path: '/reports', label: 'EXPORT_SYS', icon: AlertTriangle },
];

export function Sidebar() {
  const { alerts, mode } = useStore();
  const location = useLocation();
  const highAlerts = alerts.filter((a: any) => a.severity === 'High' || a.severity === 'Critical').length;
  const [isHovered, setIsHovered] = useState(false);

  return (
    <>
      {/* Invisible hover trigger area for expanding */}
      <div 
        className="fixed top-0 left-0 w-8 h-full z-40" 
        onMouseEnter={() => setIsHovered(true)} 
      />
      
      <m.div 
        initial={{ width: 8, opacity: 0 }}
        animate={{ width: isHovered ? 256 : 8, opacity: 1 }}
        transition={{ duration: 0.3, type: "spring", stiffness: 300, damping: 30 }}
        onMouseLeave={() => setIsHovered(false)}
        className="fixed top-0 left-0 h-full flex flex-col z-50 bg-void/80 backdrop-blur-3xl border-r overflow-hidden shadow-[10px_0_30px_rgba(0,0,0,0.8)]"
        style={{
          borderColor: isHovered ? 'rgba(0,240,255,0.3)' : 'rgba(0,240,255,0.8)',
          boxShadow: isHovered ? 'var(--shadow-glow-blue)' : '0 0 15px rgba(0,240,255,0.5)',
        }}
      >
        <AnimatePresence>
          {isHovered && (
            <m.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="flex flex-col h-full w-64 shrink-0"
            >
              {/* Logo Area */}
              <div className="h-[72px] shrink-0 flex items-center justify-start px-8 border-b border-border-dim bg-surface-active/50">
                <div className="relative flex items-center gap-3">
                  <Activity size={24} className="text-neon-blue drop-shadow-[0_0_8px_rgba(0,240,255,0.8)]" />
                  <span className="font-black tracking-[0.2em] text-white font-display text-glow-blue uppercase">HEXSNIFF</span>
                  {mode === 'live' && (
                    <div className="absolute -top-1 -right-1 w-2 h-2 rounded-full animate-pulse shadow-glow-blue bg-neon-blue" />
                  )}
                </div>
              </div>

              {/* Navigation Links */}
              <div className="flex-1 overflow-y-auto custom-scrollbar py-6 px-2">
                <div className="flex flex-col gap-2">
                  {NAV_ITEMS.map((item) => {
                    const isActive = location.pathname === item.path;
                    return (
                      <Link
                        key={item.path}
                        to={item.path}
                        className={`flex items-center gap-4 px-4 py-3 mx-2 rounded-xl transition-all duration-300 group relative overflow-hidden ${
                          isActive ? 'bg-surface-active text-white shadow-card border border-border-bright' : 'text-text-muted hover:bg-surface-hover hover:text-white border border-transparent hover:border-border-subtle'
                        }`}
                      >
                        {isActive && (
                          <m.div 
                            layoutId="active-nav-bg"
                            className="absolute inset-0 bg-gradient-to-r from-neon-blue/20 to-transparent pointer-events-none border-l-4 border-neon-blue shadow-glow-blue"
                            transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
                          />
                        )}
                        <div className="relative z-10 flex items-center gap-4 w-full">
                          <m.div
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                            transition={{ duration: 0.2 }}
                          >
                            <item.icon size={20} className={`shrink-0 transition-colors duration-300 ${isActive ? 'text-neon-blue drop-shadow-[0_0_5px_rgba(0,240,255,0.8)]' : 'group-hover:text-neon-blue'}`} />
                          </m.div>
                          
                          <span className={`text-[11px] tracking-widest uppercase font-bold flex-1 truncate transition-colors ${isActive ? 'text-glow-blue text-neon-blue' : ''}`}>
                            {item.label}
                          </span>

                          {/* High Alert Badge */}
                          {item.path === '/intel' && highAlerts > 0 && (
                            <m.div 
                              initial={{ scale: 0 }}
                              animate={{ scale: 1 }}
                              transition={{ type: "spring", stiffness: 400, damping: 25 }}
                              className="flex shrink-0 w-5 h-5 bg-crimson/20 border border-crimson/50 text-crimson rounded-full items-center justify-center text-[9px] font-bold shadow-glow-red"
                            >
                              {highAlerts > 99 ? '99+' : highAlerts}
                            </m.div>
                          )}
                        </div>
                      </Link>
                    );
                  })}
                </div>
              </div>

              {/* User / Status Area */}
              <div className="p-5 border-t border-border-dim bg-surface-active/50">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-xl bg-neon-blue/10 border border-neon-blue/30 flex items-center justify-center shrink-0 shadow-glow-blue">
                    <Shield size={20} className="text-neon-blue" />
                  </div>
                  <div className="overflow-hidden">
                    <div className="text-xs font-bold text-white truncate tracking-wide">Admin_Root</div>
                    <div className="text-[10px] text-emerald truncate font-mono uppercase tracking-widest text-glow-emerald">SYS_ONLINE</div>
                  </div>
                </div>
                <div className="mt-3 text-center text-[10px] text-text-muted font-mono tracking-widest opacity-50">
                  DEV: PINAKI
                </div>
              </div>
            </m.div>
          )}
        </AnimatePresence>
      </m.div>
    </>
  );
}
