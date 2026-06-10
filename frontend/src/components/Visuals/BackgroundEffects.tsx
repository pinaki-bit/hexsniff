import { m } from 'framer-motion';

export function BackgroundEffects() {
  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
      {/* 1. Animated Cyberpunk Grid */}
      <div 
        className="absolute inset-0 opacity-[0.03]" 
        style={{ 
          backgroundImage: 'linear-gradient(rgba(255, 255, 255, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.1) 1px, transparent 1px)', 
          backgroundSize: '40px 40px',
          animation: 'gridMove 20s linear infinite'
        }} 
      />

      {/* 2. Digital Scan Lines */}
      <div className="absolute inset-0 bg-[linear-gradient(to_bottom,rgba(255,255,255,0),rgba(255,255,255,0)_50%,rgba(0,0,0,0.1)_50%,rgba(0,0,0,0.1))] bg-[length:100%_4px] opacity-20 pointer-events-none z-50" />

      {/* 3. Scanline Animation (Bar moving down) */}
      <m.div
        animate={{ top: ['-10%', '110%'] }}
        transition={{ duration: 8, ease: "linear", repeat: Infinity }}
        className="absolute left-0 w-full h-32 bg-gradient-to-b from-transparent via-neon-blue/5 to-transparent z-40 opacity-30"
      />

      {/* 4. Radar Sweep Radial Glows */}
      <m.div
        animate={{ rotate: [0, 360] }}
        transition={{ duration: 20, ease: "linear", repeat: Infinity }}
        className="absolute -top-[50vh] -left-[50vw] w-[200vw] h-[200vh] origin-center opacity-30"
        style={{
          background: 'conic-gradient(from 0deg, transparent 0deg, rgba(0, 240, 255, 0.05) 60deg, rgba(0, 240, 255, 0.1) 90deg, transparent 90deg)'
        }}
      />
      
      {/* 5. Floating Particles (simulate data streams) */}
      <div className="absolute inset-0">
        {Array.from({ length: 15 }).map((_, i) => (
          <m.div
            key={i}
            initial={{ 
              x: Math.random() * window.innerWidth, 
              y: window.innerHeight + 100,
              opacity: Math.random() * 0.5 + 0.1
            }}
            animate={{ 
              y: -100,
              opacity: [0, 0.5, 0]
            }}
            transition={{ 
              duration: Math.random() * 10 + 10, 
              ease: "linear", 
              repeat: Infinity,
              delay: Math.random() * 20
            }}
            className="absolute w-1 h-1 bg-neon-blue rounded-full shadow-[0_0_8px_rgba(0,240,255,0.8)]"
          />
        ))}
      </div>
    </div>
  );
}
