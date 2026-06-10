import { useState, useEffect } from 'react';
import { Server, Monitor, Search, RefreshCw, AlertTriangle, Filter } from 'lucide-react';
import { m, AnimatePresence } from 'framer-motion';

interface Asset {
  ip: string;
  mac: string;
  first_seen: number;
  last_seen: number;
  open_ports: string; // JSON array string
  os_guess: string;
  risk_score: number;
}

export function AssetInventory() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeScan, setActiveScan] = useState(false);

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/assets');
      if (res.ok) {
        const data = await res.json();
        setAssets(data);
      }
    } catch (e) {
      console.error('Failed to load assets', e);
    } finally {
      setLoading(false);
    }
  };

  const triggerActiveScan = async () => {
    setActiveScan(true);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/topology/scan', { method: 'POST' });
      if (res.ok) {
        await fetchAssets();
      }
    } catch (e) {
      console.error('Active scan failed', e);
    } finally {
      setActiveScan(false);
    }
  };

  useEffect(() => {
    fetchAssets();
    const interval = setInterval(fetchAssets, 15000);
    return () => clearInterval(interval);
  }, []);

  const filteredAssets = assets.filter(a => 
    a.ip.includes(searchTerm) || 
    a.mac.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.os_guess.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col gap-6 h-full max-w-[1600px] mx-auto pb-6"
    >
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Server size={24} className="text-neon-blue" />
            <h1 className="text-2xl font-bold text-white tracking-wide">Enterprise Asset Inventory</h1>
          </div>
          <p className="text-sm font-sans text-text-muted">
            Passively discovered internal devices and services, enriched by active network scanning.
          </p>
        </div>
        
        <div className="flex gap-3 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" size={14} />
            <input 
              type="text" 
              placeholder="Search IP, MAC, OS..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-surface-active/50 border border-border-dim rounded-lg pl-9 pr-4 py-2 text-xs text-white focus:outline-none focus:border-neon-blue transition-colors font-mono"
            />
          </div>
          <button 
            onClick={triggerActiveScan} 
            disabled={activeScan}
            className="flex items-center gap-2 px-4 py-2 bg-neon-blue/10 border border-neon-blue/30 text-neon-blue rounded-lg hover:bg-neon-blue/20 transition-all text-xs font-bold uppercase tracking-widest disabled:opacity-50"
          >
            <RefreshCw size={14} className={activeScan ? "animate-spin" : ""} />
            {activeScan ? "Scanning Subnet..." : "Active Scan"}
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 rounded-xl border-t-2 border-t-neon-blue">
          <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted mb-1">Total Assets</div>
          <div className="text-2xl font-mono text-white">{assets.length}</div>
        </div>
        <div className="glass-panel p-4 rounded-xl border-t-2 border-t-purple-500">
          <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted mb-1">Identified OS</div>
          <div className="text-2xl font-mono text-purple-400">
            {assets.filter(a => a.os_guess && a.os_guess !== "Unknown").length}
          </div>
        </div>
        <div className="glass-panel p-4 rounded-xl border-t-2 border-t-orange-500">
          <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted mb-1">Assets with Open Ports</div>
          <div className="text-2xl font-mono text-orange-400">
            {assets.filter(a => JSON.parse(a.open_ports || "[]").length > 0).length}
          </div>
        </div>
        <div className="glass-panel p-4 rounded-xl border-t-2 border-t-crimson">
          <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted mb-1">Elevated Risk</div>
          <div className="text-2xl font-mono text-crimson">
            {assets.filter(a => a.risk_score > 50).length}
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="glass-panel rounded-xl flex-1 flex flex-col overflow-hidden min-h-0">
        <div className="px-5 py-3 border-b border-border-dim flex items-center justify-between bg-black/20 text-[11px] font-bold uppercase tracking-widest text-text-muted">
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-neon-blue" /> Discovered Endpoints
          </div>
        </div>
        
        <div className="flex-1 overflow-auto custom-scrollbar">
          {loading && assets.length === 0 ? (
            <div className="flex justify-center items-center h-full text-neon-blue">
              <RefreshCw className="animate-spin" size={24} />
            </div>
          ) : filteredAssets.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-text-muted p-10 opacity-60">
              <Monitor size={48} className="mb-4" />
              <div className="text-sm font-mono">No assets found.</div>
            </div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead className="sticky top-0 bg-[#060c18] border-b border-border-dim shadow-md z-10">
                <tr className="text-[9px] uppercase tracking-widest text-text-muted">
                  <th className="py-3 px-5">IP Address</th>
                  <th className="py-3 px-5">MAC Address</th>
                  <th className="py-3 px-5">Operating System</th>
                  <th className="py-3 px-5">Open Ports (Passive)</th>
                  <th className="py-3 px-5">Last Seen</th>
                  <th className="py-3 px-5">Risk</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                <AnimatePresence>
                  {filteredAssets.map((asset, idx) => {
                    const ports = JSON.parse(asset.open_ports || "[]");
                    const isStale = (Date.now() / 1000) - asset.last_seen > 3600; // 1 hour
                    
                    return (
                      <m.tr 
                        key={asset.ip}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: Math.min(idx * 0.02, 0.5) }}
                        className="border-b border-border-dim/30 hover:bg-white/5 transition-colors group"
                      >
                        <td className="py-3 px-5">
                          <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full ${isStale ? 'bg-text-muted/30' : 'bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.6)]'}`} />
                            <span className="font-bold text-white group-hover:text-neon-blue transition-colors">{asset.ip}</span>
                          </div>
                        </td>
                        <td className="py-3 px-5 text-text-muted">{asset.mac || 'N/A'}</td>
                        <td className="py-3 px-5">
                          <span className={`px-2 py-1 rounded text-[10px] ${asset.os_guess && asset.os_guess !== 'Unknown' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' : 'bg-white/5 text-text-muted'}`}>
                            {asset.os_guess || 'Unknown'}
                          </span>
                        </td>
                        <td className="py-3 px-5">
                          {ports.length > 0 ? (
                            <div className="flex flex-wrap gap-1 max-w-[200px]">
                              {ports.slice(0, 5).map((p: number) => (
                                <span key={p} className="px-1.5 py-0.5 bg-neon-blue/10 border border-neon-blue/30 text-neon-blue rounded text-[9px]">
                                  {p}
                                </span>
                              ))}
                              {ports.length > 5 && <span className="text-[9px] text-text-muted px-1">+{ports.length - 5}</span>}
                            </div>
                          ) : (
                            <span className="text-text-muted/50">-</span>
                          )}
                        </td>
                        <td className="py-3 px-5 text-text-muted text-[10px]">
                          {asset.last_seen ? new Date(asset.last_seen * 1000).toLocaleString() : 'N/A'}
                        </td>
                        <td className="py-3 px-5">
                          {asset.risk_score > 0 ? (
                            <div className="flex items-center gap-1 text-orange-400">
                              <AlertTriangle size={12} /> {asset.risk_score}
                            </div>
                          ) : (
                            <span className="text-text-muted/50">-</span>
                          )}
                        </td>
                      </m.tr>
                    );
                  })}
                </AnimatePresence>
              </tbody>
            </table>
          )}
        </div>
      </div>
    </m.div>
  );
}
