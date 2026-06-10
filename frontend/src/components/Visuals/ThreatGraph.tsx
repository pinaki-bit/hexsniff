import { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { useStore } from '../../store';
import { Network } from 'lucide-react';

export function ThreatGraph() {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const { huntGraph } = useStore();

  useEffect(() => {
    if (!huntGraph || !svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth;
    const height = containerRef.current.clientHeight;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Setup zoom and pan
    const g = svg.append('g');
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });
    svg.call(zoom);

    // Deep copy data because d3 modifies it
    const nodes = huntGraph.nodes.map((d: any) => ({ ...d }));
    const edges = huntGraph.edges.map((d: any) => ({ ...d }));

    const colorMap: Record<string, string> = {
      'asset': '#00F0FF',
      'alert': '#FF2A55',
      'case': '#FFB300',
      'attack_chain': '#00FFA3',
      'mitre': '#B388FF'
    };

    const simulation = d3.forceSimulation(nodes as any)
      .force('link', d3.forceLink(edges).id((d: any) => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide().radius(30));

    // Draw edges
    const link = g.append('g')
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke', 'rgba(255,255,255,0.15)')
      .attr('stroke-width', 1.5);

    // Edge labels
    const edgeLabels = g.append('g')
      .selectAll('text')
      .data(edges)
      .join('text')
      .attr('font-size', '8px')
      .attr('fill', 'rgba(255,255,255,0.4)')
      .attr('text-anchor', 'middle')
      .text((d: any) => d.label);

    // Draw nodes
    const node = g.append('g')
      .selectAll('circle')
      .data(nodes)
      .join('circle')
      .attr('r', (d: any) => d.type === 'case' || d.type === 'attack_chain' ? 12 : 8)
      .attr('fill', (d: any) => colorMap[d.type] || '#FFFFFF')
      .attr('stroke', 'rgba(0,0,0,0.5)')
      .attr('stroke-width', 2)
      .call(d3.drag<SVGCircleElement, any>()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        }) as any);

    // Add node glows
    node.style('filter', (d: any) => `drop-shadow(0 0 8px ${colorMap[d.type]})`);

    // Node labels
    const label = g.append('g')
      .selectAll('text')
      .data(nodes)
      .join('text')
      .text((d: any) => d.label)
      .attr('font-size', '10px')
      .attr('fill', '#FFFFFF')
      .attr('dx', 15)
      .attr('dy', 4);

    // Node click to pivot (Optional: could trigger store.pivotHunt)
    node.on('click', (_event, d: any) => {
       console.log('Clicked node', d);
    });

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      edgeLabels
        .attr('x', (d: any) => (d.source.x + d.target.x) / 2)
        .attr('y', (d: any) => (d.source.y + d.target.y) / 2 - 5);

      node
        .attr('cx', (d: any) => d.x)
        .attr('cy', (d: any) => d.y);

      label
        .attr('x', (d: any) => d.x)
        .attr('y', (d: any) => d.y);
    });

    return () => {
      simulation.stop();
    };
  }, [huntGraph]);

  return (
    <div className="glass-panel flex-1 rounded-2xl flex flex-col overflow-hidden relative shadow-card" ref={containerRef}>
        <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-surface-active/50 z-10 shrink-0">
            <div className="flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest">
                <Network size={14} className="text-neon-blue" />
                Evidence Graph
            </div>
            {huntGraph && (
                <div className="text-[10px] font-mono text-text-muted">
                    {huntGraph.nodes.length} Nodes | {huntGraph.edges.length} Edges
                </div>
            )}
        </div>
        <div className="flex-1 bg-void relative overflow-hidden">
            {!huntGraph ? (
                <div className="absolute inset-0 flex items-center justify-center text-text-muted text-xs uppercase tracking-widest animate-pulse">
                    Initializing Knowledge Graph...
                </div>
            ) : (
                <svg ref={svgRef} className="w-full h-full cursor-move" />
            )}
            
            {/* Legend */}
            <div className="absolute bottom-4 left-4 bg-surface backdrop-blur-md border border-border-dim p-3 rounded-lg flex flex-col gap-2">
                <div className="text-[10px] uppercase font-bold text-white mb-1 tracking-widest">Entities</div>
                {[
                    { label: 'Asset', color: '#00F0FF' },
                    { label: 'Alert', color: '#FF2A55' },
                    { label: 'Attack Chain', color: '#00FFA3' },
                    { label: 'Case', color: '#FFB300' }
                ].map(item => (
                    <div key={item.label} className="flex items-center gap-2 text-[10px] text-text-muted">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color, boxShadow: `0 0 5px ${item.color}` }} />
                        {item.label}
                    </div>
                ))}
            </div>
        </div>
    </div>
  );
}
