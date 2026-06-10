import { useEffect, useRef, useMemo, useState } from 'react';
import { Zap, Play, RefreshCw, Network, Server, ShieldAlert } from 'lucide-react';
import { useStore } from '../store';
import * as d3 from 'd3';
import { m } from 'framer-motion';

interface Node extends d3.SimulationNodeDatum {
  id: string;
  ip: string;
  role: 'gateway' | 'internal' | 'external' | 'threat';
  packets: number;
  color: string;
  mac?: string;
  vendor?: string;
}

interface Link {
  source: string;
  target: string;
  proto: string;
  weight: number;
}

const ROLE_COLORS = {
  gateway: '#00E5FF',
  internal: '#FFFFFF',
  external: '#8b949e',
  threat: '#FF2A55',
};

function isInternal(ip: string) {
  return ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === 'N/A';
}

function isThreatIP(ip: string, alerts: any[]) {
  return alerts.some(a => a.message?.includes(ip) || a.packetId?.includes(ip));
}

export function NetworkTopology() {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const { packets, alerts } = useStore();

  const [scannedHosts, setScannedHosts] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);
  const [subnetInput, setSubnetInput] = useState('192.168.1.0/24');

  const triggerScan = async () => {
    setScanning(true);
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/topology/scan?subnet=${encodeURIComponent(subnetInput)}`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setScannedHosts(data.hosts || []);
      }
    } catch (e) {
      console.error("Discovery scan failed:", e);
    } finally {
      setScanning(false);
    }
  };

  const { nodes, links } = useMemo(() => {
    const ipSet = new Map<string, { packets: number; outgoing: Set<string>; mac?: string; vendor?: string }>();
    const linkMap = new Map<string, { proto: string; weight: number }>();

    packets.forEach(p => {
      if (!p.src_ip || p.src_ip === 'N/A') return;
      if (!ipSet.has(p.src_ip)) ipSet.set(p.src_ip, { packets: 0, outgoing: new Set(), mac: p.src_mac });
      if (!ipSet.has(p.dst_ip)) ipSet.set(p.dst_ip, { packets: 0, outgoing: new Set(), mac: p.dst_mac });
      
      ipSet.get(p.src_ip)!.packets++;
      ipSet.get(p.src_ip)!.outgoing.add(p.dst_ip);

      const key = `${p.src_ip}->${p.dst_ip}`;
      const existing = linkMap.get(key);
      if (existing) existing.weight++;
      else linkMap.set(key, { proto: p.proto, weight: 1 });
    });

    const passiveNodes: Node[] = Array.from(ipSet.entries()).map(([ip, data]) => {
      const threat = isThreatIP(ip, alerts);
      const role: Node['role'] = threat ? 'threat' : ip === '0.0.0.0' || ip.endsWith('.1') ? 'gateway' : isInternal(ip) ? 'internal' : 'external';
      return { 
        id: ip, ip, role, packets: data.packets, color: ROLE_COLORS[role], mac: data.mac 
      };
    });

    const scannedNodes: Node[] = scannedHosts.map(h => {
      const threat = isThreatIP(h.ip, alerts);
      const role: Node['role'] = threat ? 'threat' : h.ip.endsWith('.1') ? 'gateway' : 'internal';
      return {
        id: h.ip, ip: h.ip, role, packets: 0, color: ROLE_COLORS[role], mac: h.mac, vendor: h.vendor
      };
    });

    const mergedNodes = new Map<string, Node>();
    passiveNodes.forEach(n => mergedNodes.set(n.id, n));
    scannedNodes.forEach(n => {
      if (!mergedNodes.has(n.id)) {
        mergedNodes.set(n.id, n);
      } else {
        const existing = mergedNodes.get(n.id)!;
        existing.mac = n.mac || existing.mac;
        existing.vendor = n.vendor || existing.vendor;
      }
    });

    const nodesList = Array.from(mergedNodes.values()).slice(0, 100);
    const nodeIds = new Set(nodesList.map(n => n.id));

    const trafficLinks: Link[] = Array.from(linkMap.entries())
      .filter(([k]) => {
        const [s, t] = k.split('->');
        return nodeIds.has(s) && nodeIds.has(t);
      })
      .map(([k, v]) => {
        const [source, target] = k.split('->');
        return { source, target, proto: v.proto, weight: v.weight };
      });

    const linksList = Array.from(trafficLinks).slice(0, 150);

    return { nodes: nodesList, links: linksList };
  }, [packets, alerts, scannedHosts]);

  const stats = useMemo(() => ({
    nodes: nodes.length,
    links: links.length,
    threats: nodes.filter(n => n.role === 'threat').length
  }), [nodes, links]);

  useEffect(() => {    
    if (!svgRef.current || nodes.length === 0) return;

    const el = svgRef.current;
    const W = el.clientWidth || 800;
    const H = el.clientHeight || 600;

    d3.select(el).selectAll('*').remove();

    const svg = d3.select(el)
      .attr('width', W)
      .attr('height', H);

    // Zoom container
    const g = svg.append('g');

    // Zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    const defs = svg.append('defs');
    const glow = defs.append('filter').attr('id', 'topo-glow');
    glow.append('feGaussianBlur').attr('stdDeviation', 4).attr('result', 'coloredBlur');
    const merge = glow.append('feMerge');
    merge.append('feMergeNode').attr('in', 'coloredBlur');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');

    const sim = d3.forceSimulation<Node>(nodes as Node[])
      .force('link', d3.forceLink<Node, any>(links).id(d => d.id).distance(100).strength(0.3))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide(30));

    const link = g.append('g').selectAll('line').data(links).enter().append('line')
      .attr('stroke', d => d.proto === 'TCP' ? 'rgba(0, 229, 255, 0.2)' : d.proto === 'UDP' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(139,92,246,0.2)')
      .attr('stroke-width', d => Math.min(Math.log(d.weight + 1) + 0.5, 3));

    const nodeGroup = g.append('g').selectAll('g').data(nodes as Node[]).enter().append('g')
      .style('cursor', 'pointer');

    nodeGroup.append('circle')
      .attr('r', d => Math.min(Math.log(d.packets + 2) * 5 + 8, 24))
      .attr('fill', d => d.color)
      .attr('fill-opacity', 0.15)
      .attr('stroke', d => d.color)
      .attr('stroke-width', d => d.role === 'threat' ? 2 : 1)
      .attr('filter', d => (d.role === 'threat' || d.role === 'gateway') ? 'url(#topo-glow)' : '')
      .style('transition', 'all 0.3s ease');

    nodeGroup.append('text')
      .text(d => d.ip.split('.').slice(-2).join('.'))
      .attr('text-anchor', 'middle')
      .attr('dy', d => Math.min(Math.log(d.packets + 2) * 5 + 8, 24) + 14)
      .attr('fill', '#a1a1aa')
      .style('font-size', '10px')
      .style('font-family', 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace')
      .style('pointer-events', 'none');

    const tooltip = d3.select(containerRef.current)
      .append('div')
      .style('position', 'absolute')
      .style('display', 'none')
      .style('background', 'rgba(7, 11, 20, 0.9)')
      .style('backdrop-filter', 'blur(12px)')
      .style('border', '1px solid rgba(255, 255, 255, 0.1)')
      .style('border-radius', '12px')
      .style('padding', '12px 16px')
      .style('font-size', '12px')
      .style('font-family', 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace')
      .style('color', '#fff')
      .style('pointer-events', 'none')
      .style('z-index', '100')
      .style('box-shadow', '0 8px 32px rgba(0,0,0,0.5)');

    nodeGroup
      .on('mouseover', (event, d) => {
        d3.select(event.currentTarget).select('circle').attr('fill-opacity', 0.3).attr('stroke-width', 2);
        tooltip
          .style('display', 'flex')
          .style('flex-direction', 'column')
          .style('gap', '4px')
          .style('left', `${event.offsetX + 20}px`)
          .style('top', `${event.offsetY - 20}px`)
          .html(`
            <div style="color:${d.color};font-weight:700;font-size:14px;margin-bottom:4px;display:flex;align-items:center;gap:6px;">
              <div style="width:6px;height:6px;border-radius:50%;background:${d.color};box-shadow:0 0 8px ${d.color};"></div>
              ${d.ip}
            </div>
            <div style="color:#a1a1aa;display:flex;justify-content:space-between;width:160px;"><span>Role:</span> <span style="color:#fff">${d.role.toUpperCase()}</span></div>
            <div style="color:#a1a1aa;display:flex;justify-content:space-between;width:160px;"><span>Traffic:</span> <span style="color:#fff">${d.packets} PKTS</span></div>
            ${d.mac ? `<div style="color:#a1a1aa;display:flex;justify-content:space-between;width:160px;"><span>MAC:</span> <span style="color:#fff">${d.mac}</span></div>` : ''}
            ${d.vendor ? `<div style="color:#a1a1aa;display:flex;justify-content:space-between;width:160px;"><span>Vendor:</span> <span style="color:#00E5FF">${d.vendor}</span></div>` : ''}
          `);
      })
      .on('mousemove', (event) => {
        tooltip
          .style('left', `${event.offsetX + 20}px`)
          .style('top', `${event.offsetY - 20}px`);
      })
      .on('mouseout', (event) => {
        d3.select(event.currentTarget).select('circle').attr('fill-opacity', 0.15).attr('stroke-width', (d: any) => d.role === 'threat' ? 2 : 1);
        tooltip.style('display', 'none');
      });

    nodeGroup.call(
      d3.drag<any, Node>()
        .on('start', (event, d) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on('end', (event, d) => { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
    );

    sim.on('tick', () => {
      link
        .attr('x1', d => (d.source as any).x)
        .attr('y1', d => (d.source as any).y)
        .attr('x2', d => (d.target as any).x)
        .attr('y2', d => (d.target as any).y);

      nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => { sim.stop(); tooltip.remove(); };
  }, [nodes, links]);

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.32, 0.72, 0, 1] }}
      className="flex flex-col gap-6 h-full max-w-[1800px] mx-auto pb-6"
    >
      {/* ── KPI Grid ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
        {[
          { label: 'Discovered Nodes', val: stats.nodes, icon: Server, color: 'text-white' },
          { label: 'Inter-Host Links', val: stats.links, icon: Network, color: 'text-text-muted' },
          { label: 'Threat Nodes', val: stats.threats, icon: ShieldAlert, color: stats.threats > 0 ? 'text-crimson' : 'text-neon-blue' },
          { label: 'Protocols In-Use', val: new Set(links.map(l => l.proto)).size || 0, icon: Zap, color: 'text-white' },
        ].map((kpi, i) => (
          <m.div 
            key={kpi.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: i * 0.1, ease: [0.32, 0.72, 0, 1] }}
            className="glass-panel p-5 rounded-xl flex items-center gap-5 group shadow-card"
          >
            <div className={`w-12 h-12 rounded-full border border-border-dim bg-white/5 flex items-center justify-center shrink-0 transition-colors duration-500 group-hover:bg-white/10 ${kpi.color}`}>
              <kpi.icon size={20} />
            </div>
            <div>
              <div className="text-xs font-sans text-text-muted mb-1">{kpi.label}</div>
              <div className={`text-2xl font-mono font-medium tracking-tight ${kpi.color}`}>
                {kpi.val.toLocaleString()}
              </div>
            </div>
          </m.div>
        ))}
      </div>

      <div className="flex flex-col lg:flex-row gap-6 flex-1 min-h-0">
        
        {/* ── Scan Controls Sidebar ── */}
        <div className="glass-panel rounded-xl flex flex-col w-full lg:w-[320px] shrink-0 shadow-card overflow-hidden h-fit">
          <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02]">
            <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
              <Zap size={14} className="text-neon-blue" /> Discovery Scanner
            </div>
          </div>
          <div className="p-5 flex flex-col gap-4">
            <div>
              <div className="text-xs font-sans text-text-muted mb-2">Target Subnet</div>
              <input
                className="w-full bg-surface/50 border border-border-dim text-text-main text-xs font-mono rounded-lg p-3 outline-none focus:border-neon-blue focus:ring-1 focus:ring-neon-blue transition-all"
                value={subnetInput}
                onChange={e => setSubnetInput(e.target.value)}
                placeholder="192.168.1.0/24"
                disabled={scanning}
              />
            </div>
            
            <button
              className="w-full flex items-center justify-center gap-2 bg-neon-blue/10 hover:bg-neon-blue/20 text-neon-blue border border-neon-blue/30 p-3 rounded-lg text-xs font-sans font-semibold transition-all shadow-glow-blue disabled:opacity-50 disabled:cursor-not-allowed"
              onClick={triggerScan}
              disabled={scanning}
            >
              {scanning ? <RefreshCw className="animate-spin" size={14} /> : <Play size={14} />}
              {scanning ? 'Sweeping Subnet...' : 'Execute Sweep'}
            </button>
            
            <p className="text-[10px] text-text-muted mt-2 font-sans leading-relaxed">
              ARP sweeping identifies active network interfaces on the local broadcast domain and attempts to resolve NIC vendor data.
            </p>
          </div>
        </div>

        {/* ── Graph Visualization Engine ── */}
        <div className="glass-panel rounded-xl flex-1 flex flex-col shadow-card overflow-hidden min-h-[400px]">
          <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-white/[0.02] z-10 shrink-0">
            <div className="flex items-center gap-2 text-xs font-sans font-semibold text-white">
              <Network size={14} className="text-neon-blue" /> Tactical Topology Map
            </div>
            <div className="flex items-center gap-4">
              {[
                { label: 'Gateway', color: ROLE_COLORS.gateway },
                { label: 'Internal', color: ROLE_COLORS.internal },
                { label: 'External', color: ROLE_COLORS.external },
                { label: 'Threat', color: ROLE_COLORS.threat },
              ].map(({ label, color }) => (
                <div key={label} className="flex items-center gap-1.5 text-[10px] font-sans font-semibold text-text-muted uppercase tracking-wider">
                  <span className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
                  {label}
                </div>
              ))}
            </div>
          </div>
          
          <div className="flex-1 relative bg-void overflow-hidden" ref={containerRef}>
            {/* Background Ambience */}
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(0,229,255,0.02)_0%,transparent_70%)] pointer-events-none" />
            <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.01)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.01)_1px,transparent_1px)] bg-[size:40px_40px] pointer-events-none" />
            
            {nodes.length === 0 ? (
              <div className="absolute inset-0 flex flex-col items-center justify-center text-text-muted opacity-50">
                <Network size={48} className="mb-4" />
                <p className="text-sm font-sans tracking-wide">Awaiting Network Telemetry</p>
              </div>
            ) : (
              <svg ref={svgRef} className="absolute inset-0 w-full h-full cursor-grab active:cursor-grabbing" />
            )}
          </div>
        </div>

      </div>
    </m.div>
  );
}
