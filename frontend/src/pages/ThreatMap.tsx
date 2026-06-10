import { useMemo, useState } from 'react';
import { Globe2, TrendingUp, Crosshair, Network, ShieldAlert } from 'lucide-react';
import MapLibreMap, { Marker, Source, Layer, Popup } from 'react-map-gl/maplibre';
import 'maplibre-gl/dist/maplibre-gl.css';
import { useStore } from '../store';
import type { GeoData } from '../store';
import { m, AnimatePresence } from 'framer-motion';

const mapStyle = {
  version: 8 as const,
  sources: {
    osm: {
      type: 'raster' as const,
      tiles: ['https://tile.openstreetmap.org/{z}/{x}/{y}.png'],
      tileSize: 256
    }
  },
  layers: [
    {
      id: 'osm',
      type: 'raster' as const,
      source: 'osm',
      minzoom: 0,
      maxzoom: 19
    }
  ]
};

export function ThreatMap() {
  const { packets, alerts } = useStore();
  const [activeMarker, setActiveMarker] = useState<string | null>(null);

  const mapData = useMemo(() => {
    const lines: Array<{ from: {lat: number, lng: number}; to: {lat: number, lng: number}; threat: boolean; label: string }> = [];
    const points = new Map<string, {
      lat: number; lng: number; 
      country: string; city: string; isp?: string; asn?: string;
      threats: number; hits: number;
    }>();

    const isValidGeo = (g?: GeoData) => g && typeof g.lat === 'number' && typeof g.lon === 'number' && !(g.lat === 0 && g.lon === 0);

    packets.slice(-100).forEach(p => {
      const sg = p.src_geo, dg = p.dst_geo;
      const isThreat = !!(p.alerts && p.alerts.length > 0);

      const extract = (g?: GeoData) => {
        if (isValidGeo(g)) {
          const key = `${g!.lat},${g!.lon}`;
          if (!points.has(key)) {
            points.set(key, {
              lat: g!.lat as number,
              lng: g!.lon as number,
              country: g!.country,
              city: g!.city,
              isp: g!.isp,
              asn: g!.asn,
              threats: 0, hits: 0
            });
          }
          const pt = points.get(key)!;
          pt.hits += 1;
          if (isThreat) pt.threats += 1;
        }
      };

      extract(sg);
      extract(dg);

      if (isValidGeo(sg) && isValidGeo(dg)) {
        lines.push({
          from: { lat: sg!.lat as number, lng: sg!.lon as number },
          to: { lat: dg!.lat as number, lng: dg!.lon as number },
          threat: isThreat,
          label: isThreat ? p.alerts![0].category : p.proto
        });
      }
    });

    return { 
      points: Array.from(points.values()), 
      lines
    };
  }, [packets]);

  const arcsGeoJSON = useMemo(() => {
    const features = mapData.lines.map((l) => ({
      type: 'Feature' as const,
      geometry: {
        type: 'LineString' as const,
        coordinates: [
          [l.from.lng, l.from.lat],
          [l.to.lng, l.to.lat]
        ]
      },
      properties: {
        threat: l.threat
      }
    }));
    return { type: 'FeatureCollection' as const, features };
  }, [mapData.lines]);

  const topISPs = useMemo(() => {
    const counts: Record<string, number> = {};
    mapData.points.forEach(pt => {
      if (pt.isp && pt.isp !== 'Unknown' && pt.isp !== 'Local' && pt.isp !== 'Resolving...' && pt.isp !== 'Error') {
        counts[pt.isp] = (counts[pt.isp] || 0) + pt.hits;
      }
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [mapData]);

  const topCountries = useMemo(() => {
    const counts: Record<string, number> = {};
    mapData.points.forEach(pt => {
      counts[pt.country] = (counts[pt.country] || 0) + pt.hits;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [mapData]);

  const hasGeoData = mapData.points.length > 0;
  const activeMarkerPoint = activeMarker ? mapData.points.find(p => `${p.lat},${p.lng}` === activeMarker) : null;

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col gap-6 h-full max-w-[1600px] mx-auto pb-6"
    >
      {/* ── KPI Grid ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
        {[
          { label: 'Active Geo Nodes', val: mapData.points.length, icon: Globe2, color: 'text-neon-blue text-glow-blue' },
          { label: 'Identified ISPs', val: topISPs.length, icon: Network, color: 'text-text-main' },
          { label: 'Threat Arcs', val: mapData.lines.filter(l => l.threat).length, icon: ShieldAlert, color: 'text-crimson text-glow-red' },
          { label: 'Countries Visualized', val: topCountries.length, icon: TrendingUp, color: 'text-text-main' },
        ].map((kpi, i) => (
          <m.div 
            key={kpi.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: i * 0.1, ease: [0.16, 1, 0.3, 1] }}
            className="glass-panel p-5 rounded-2xl flex items-center gap-5 group"
          >
            <div className={`w-12 h-12 rounded-full bg-surface border border-border-dim flex items-center justify-center shrink-0 transition-all duration-500 group-hover:bg-white/10 group-hover:scale-110 ${kpi.color}`}>
              <kpi.icon size={18} />
            </div>
            <div>
              <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted mb-1">{kpi.label}</div>
              <div className={`text-xl font-mono font-bold ${kpi.color}`}>{kpi.val.toLocaleString()}</div>
            </div>
          </m.div>
        ))}
      </div>

      <div className="flex flex-col lg:flex-row gap-6 flex-1 min-h-0">
        
        {/* ── MapLibre Engine ── */}
        <div className="glass-panel rounded-2xl flex-1 flex flex-col overflow-hidden min-h-[400px] shadow-card">
          <div className="px-5 py-4 border-b border-border-dim flex justify-between items-center bg-surface-active/50 shrink-0 z-10">
            <div className="flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest">
              <Globe2 size={14} className="text-neon-blue" /> Geospatial Intelligence Node
            </div>
            {hasGeoData ? (
              <span className="text-[10px] font-bold text-neon-blue animate-pulse flex items-center gap-2 uppercase tracking-widest">
                <span className="w-1.5 h-1.5 rounded-full bg-neon-blue shadow-glow-blue" /> GEO-IP ACTIVE
              </span>
            ) : (
              <span className="text-[10px] font-bold text-text-muted flex items-center gap-2 uppercase tracking-widest">
                <span className="w-1.5 h-1.5 rounded-full bg-text-muted" /> AWAITING DATA
              </span>
            )}
          </div>
          
          <div className="flex-1 relative map-container-dark bg-void">
            <MapLibreMap
              initialViewState={{ longitude: 0, latitude: 20, zoom: 1.5 }}
              mapStyle={mapStyle}
              interactiveLayerIds={['osm']}
              style={{ width: '100%', height: '100%' }}
            >
              {/* Arcs Source & Layer */}
              <Source id="arcs" type="geojson" data={arcsGeoJSON}>
                <Layer
                  id="arc-line"
                  type="line"
                  paint={{
                    'line-color': ['case', ['get', 'threat'], '#FF2A55', '#00F0FF'],
                    'line-width': ['case', ['get', 'threat'], 2, 1],
                    'line-opacity': ['case', ['get', 'threat'], 0.8, 0.4]
                  }}
                />
              </Source>

              {/* GeoIP Markers */}
              {mapData.points.map((pt) => {
                const key = `${pt.lat},${pt.lng}`;
                const isThreat = pt.threats > 0;
                return (
                  <Marker
                    key={key}
                    longitude={pt.lng}
                    latitude={pt.lat}
                    anchor="center"
                    onClick={(e) => {
                      e.originalEvent.stopPropagation();
                      setActiveMarker(key);
                    }}
                  >
                    <div className="relative group">
                      {isThreat && <div className="absolute inset-0 bg-crimson rounded-full animate-ping opacity-50 shadow-glow-red" />}
                      <div
                        className={`w-3 h-3 md:w-4 md:h-4 rounded-full border border-white/50 cursor-pointer transition-transform group-hover:scale-125 ${
                          isThreat ? 'bg-crimson shadow-glow-red' : 'bg-neon-blue shadow-glow-blue'
                        }`}
                      />
                    </div>
                  </Marker>
                );
              })}

              {/* Info Popup */}
              {activeMarkerPoint && (
                <Popup
                  longitude={activeMarkerPoint.lng}
                  latitude={activeMarkerPoint.lat}
                  anchor="bottom"
                  onClose={() => setActiveMarker(null)}
                  closeOnClick={false}
                  offset={12}
                  className="glass-popup"
                  style={{ background: 'transparent' }}
                >
                  <div className="bg-surface/90 backdrop-blur-2xl border border-border-dim shadow-modal p-4 rounded-xl text-text-main text-xs min-w-[200px]">
                    <div className="font-bold border-b border-white/10 pb-2 mb-3 font-sans uppercase tracking-widest text-neon-blue text-glow-blue">
                      {activeMarkerPoint.city || 'Unknown City'}, {activeMarkerPoint.country}
                    </div>
                    <div className="flex flex-col gap-2 font-mono text-[10px]">
                      {activeMarkerPoint.asn && <div className="flex justify-between"><span className="text-text-muted">ASN:</span> <span className="text-white">{activeMarkerPoint.asn}</span></div>}
                      {activeMarkerPoint.isp && <div className="flex justify-between"><span className="text-text-muted">ISP:</span> <span className="text-white truncate max-w-[100px]" title={activeMarkerPoint.isp}>{activeMarkerPoint.isp}</span></div>}
                      <div className="flex justify-between"><span className="text-text-muted">HITS:</span> <span className="text-white">{activeMarkerPoint.hits}</span></div>
                      {activeMarkerPoint.threats > 0 && (
                        <div className="text-crimson font-bold mt-2 pt-2 border-t border-crimson/20 flex justify-between text-glow-red">
                          <span>THREATS:</span> <span>{activeMarkerPoint.threats}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </Popup>
              )}
            </MapLibreMap>
            {/* Global Overlay Vignette */}
            <div className="absolute inset-0 pointer-events-none shadow-[inset_0_0_100px_rgba(3,7,18,1)]" />
          </div>
        </div>

        {/* ── Intelligence Panels ── */}
        <div className="flex flex-col gap-6 lg:w-[340px] shrink-0 overflow-y-auto custom-scrollbar">
          
          <div className="glass-panel rounded-2xl flex flex-col overflow-hidden shadow-card">
            <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-bold text-white bg-surface-active/50 uppercase tracking-widest">
              <Network size={14} className="text-neon-blue" /> ISP Intelligence
            </div>
            <div className="p-4 flex flex-col gap-4">
              {topISPs.length === 0 ? (
                <div className="text-center text-text-muted text-xs italic py-2">No ISP data</div>
              ) : topISPs.map(([isp, hits]) => (
                <div key={isp}>
                  <div className="flex justify-between text-[10px] font-mono mb-1.5">
                    <span className="text-white truncate pr-2">{isp}</span>
                    <span className="text-text-muted shrink-0">{hits}</span>
                  </div>
                  <div className="h-1 bg-void rounded-full overflow-hidden border border-white/5">
                    <m.div 
                      initial={{ width: 0 }} animate={{ width: `${(hits / topISPs[0][1]) * 100}%` }}
                      transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
                      className="h-full bg-neon-blue shadow-glow-blue rounded-full"
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-panel rounded-2xl flex flex-col overflow-hidden shadow-card">
            <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-bold text-white bg-surface-active/50 uppercase tracking-widest">
              <TrendingUp size={14} className="text-neon-blue" /> Regional Index
            </div>
            <div className="p-4 flex flex-col gap-4">
              {topCountries.length === 0 ? (
                <div className="text-center text-text-muted text-xs italic py-2">No Country data</div>
              ) : topCountries.map(([c, hits]) => (
                <div key={c}>
                  <div className="flex justify-between text-[10px] font-mono mb-1.5">
                    <span className="text-white truncate pr-2">{c}</span>
                    <span className="text-text-muted shrink-0">{hits}</span>
                  </div>
                  <div className="h-1 bg-void rounded-full overflow-hidden border border-white/5">
                    <m.div 
                      initial={{ width: 0 }} animate={{ width: `${(hits / topCountries[0][1]) * 100}%` }}
                      transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
                      className="h-full bg-white/50 rounded-full"
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-panel rounded-2xl flex flex-col overflow-hidden flex-1 min-h-[200px] shadow-card">
            <div className="px-5 py-4 border-b border-border-dim flex items-center gap-2 text-xs font-bold text-white bg-surface-active/50 uppercase tracking-widest">
              <Crosshair size={14} className="text-crimson" /> Threat Feed
            </div>
            <div className="p-3 flex flex-col gap-2 overflow-y-auto">
              {alerts.length === 0 ? (
                <div className="text-center text-emerald text-glow-emerald text-[10px] uppercase font-bold tracking-widest py-8">
                  No Active Threats
                </div>
              ) : (
                <AnimatePresence>
                  {alerts.slice(-10).reverse().map(a => (
                    <m.div 
                      key={a.id}
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      className="text-[10px] p-3 bg-crimson/5 border border-crimson/10 border-l-2 border-l-crimson rounded-lg group hover:bg-crimson/10 transition-colors mb-1"
                    >
                      <div className="text-crimson font-bold mb-1.5 truncate text-glow-red tracking-wide uppercase">{a.category}</div>
                      <div className="font-mono text-text-muted group-hover:text-text-main transition-colors truncate">
                        {a.src_ip} → {a.dst_ip}
                      </div>
                    </m.div>
                  ))}
                </AnimatePresence>
              )}
            </div>
          </div>

        </div>

      </div>
    </m.div>
  );
}
