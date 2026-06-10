import { useStore } from '../../store';
import { m, AnimatePresence } from 'framer-motion';
import { AlertTriangle, Activity } from 'lucide-react';
import { useEffect, useState } from 'react';

export function StatusBar() {
  const { mode, packets, packetRate, alerts, backendError } = useStore();
  const [now, setNow] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const int = setInterval(() => setNow(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(int);
  }, []);

  return (
    <m.div 
      initial={{ y: 50, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: [0.32, 0.72, 0, 1] }}
      className="h-10 shrink-0 bg-surface/80 backdrop-blur-md border-t border-border-dim flex items-center px-6 justify-between text-[10px] font-mono text-text-muted z-40 transition-colors duration-300 uppercase"
    >
      
      <div className={`flex items-center gap-2 ${mode ? 'text-neon-blue' : 'text-text-muted'}`}>
        <Activity size={12} className={mode === 'live' ? 'animate-pulse' : ''} />
        {mode === 'live' ? 'MONITORING_ACTIVE' : mode === 'replay' ? 'SIMULATION_ACTIVE' : 'SYSTEM_IDLE'}
      </div>

      <div className="flex items-center gap-4 text-white">
        <span>PKT: {packets.length.toLocaleString()}</span>
        <span>PPS: {packetRate}</span>
        <span className="text-neon-blue">v4.0.0_AEGIS</span>
      </div>

      <AnimatePresence>
        {alerts.length > 0 && (
          <m.div 
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0 }}
            className="flex items-center gap-1.5 px-2 py-0.5 bg-crimson/10 border border-crimson text-crimson font-bold"
          >
            <AlertTriangle size={10} className="animate-pulse" />
            {alerts.length} THREATS DETECTED
          </m.div>
        )}
      </AnimatePresence>

      <div className="ml-auto flex items-center gap-6">
        <div className="flex items-center gap-1.5">
          <div className={`w-1.5 h-1.5 rounded-full ${backendError ? 'bg-crimson animate-pulse' : 'bg-neon-blue'}`} />
          {backendError ? <span className="text-crimson">OFFLINE</span> : 'UPLINK_STABLE'}
        </div>
        <span className="ml-4 opacity-50 border-l border-border-dim pl-6">{now}</span>
      </div>
      
    </m.div>
  );
}
