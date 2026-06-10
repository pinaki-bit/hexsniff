import { useState, useEffect, useRef } from 'react';
import { m, AnimatePresence } from 'framer-motion';

interface BootSequenceProps {
  onComplete: () => void;
}

function BootingVisualizer() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = canvas.width = 600;
    let height = canvas.height = 600;
    let animationFrameId: number;
    let time = 0;

    // Generate Globe Nodes
    const globeNodes: any[] = [];
    const numGlobeNodes = 300;
    for (let i = 0; i < numGlobeNodes; i++) {
      const phi = Math.acos(-1 + (2 * i) / numGlobeNodes);
      const theta = Math.sqrt(numGlobeNodes * Math.PI) * phi;
      globeNodes.push({
        x: Math.cos(theta) * Math.sin(phi),
        y: Math.sin(theta) * Math.sin(phi),
        z: Math.cos(phi)
      });
    }

    // Generate Data Uplink Beams
    const beams: any[] = [];
    for (let i = 0; i < 40; i++) {
      beams.push({
        angle: Math.random() * Math.PI * 2,
        radius: 140 + Math.random() * 80,
        speed: 0.02 + Math.random() * 0.05,
        height: Math.random() * 200,
        yOffset: (Math.random() - 0.5) * 400
      });
    }

    const render = () => {
      time += 0.01;
      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;
      const globeRadius = 100;

      // Draw Orbital Rings (3D rotated ellipses)
      const rings = [
        { r: 200, rotX: 1.2, rotY: time * 0.5, rotZ: 0.2, color: 'rgba(0, 229, 255, 0.4)', dash: [2, 4] },
        { r: 220, rotX: -0.8, rotY: -time * 0.3, rotZ: 0.5, color: 'rgba(255, 255, 255, 0.2)', dash: [20, 10, 2, 10] },
        { r: 260, rotX: 1.5, rotY: time * 0.2, rotZ: -0.1, color: 'rgba(0, 229, 255, 0.1)', dash: [] }
      ];

      rings.forEach(ring => {
        ctx.beginPath();
        ctx.strokeStyle = ring.color;
        ctx.lineWidth = 1;
        if (ring.dash.length) ctx.setLineDash(ring.dash);
        else ctx.setLineDash([]);

        for (let a = 0; a <= Math.PI * 2 + 0.1; a += 0.05) {
          let x = Math.cos(a) * ring.r;
          let y = Math.sin(a) * ring.r;
          let z = 0;

          // Rotate X
          let y1 = y * Math.cos(ring.rotX) - z * Math.sin(ring.rotX);
          let z1 = y * Math.sin(ring.rotX) + z * Math.cos(ring.rotX);
          // Rotate Z
          let x2 = x * Math.cos(ring.rotZ) - y1 * Math.sin(ring.rotZ);
          let y2 = x * Math.sin(ring.rotZ) + y1 * Math.cos(ring.rotZ);
          // Rotate Y
          let x3 = x2 * Math.cos(ring.rotY) + z1 * Math.sin(ring.rotY);
          
          if (a === 0) ctx.moveTo(cx + x3, cy + y2);
          else ctx.lineTo(cx + x3, cy + y2);
        }
        ctx.stroke();
      });
      ctx.setLineDash([]);

      // Draw Data Uplink Beams
      beams.forEach(b => {
        b.yOffset -= b.speed * 100;
        if (b.yOffset < -300) b.yOffset = 300;

        let x = Math.cos(b.angle + time * 0.2) * b.radius;
        let z = Math.sin(b.angle + time * 0.2) * b.radius;

        // Apply slight global tilt to match a ring
        let rotX = 1.2;
        let yBase = 0;
        let y1 = yBase * Math.cos(rotX) - z * Math.sin(rotX);
        let z1 = yBase * Math.sin(rotX) + z * Math.cos(rotX);

        let screenX = cx + x;
        let screenYBase = cy + y1;

        const alpha = Math.max(0, 1 - Math.abs(b.yOffset) / 200) * 0.6;
        
        if (z1 > 0) { // Only draw front beams
          const grad = ctx.createLinearGradient(0, screenYBase + b.yOffset, 0, screenYBase + b.yOffset - b.height);
          grad.addColorStop(0, `rgba(0, 229, 255, 0)`);
          grad.addColorStop(0.5, `rgba(0, 229, 255, ${alpha})`);
          grad.addColorStop(1, `rgba(0, 229, 255, 0)`);

          ctx.strokeStyle = grad;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(screenX, screenYBase + b.yOffset);
          ctx.lineTo(screenX, screenYBase + b.yOffset - b.height);
          ctx.stroke();
        }
      });

      // Draw Globe
      const globeRotY = time * 0.8;
      const globeRotX = 0.4;
      const projectedNodes: any[] = [];

      globeNodes.forEach(n => {
        let y1 = n.y * Math.cos(globeRotX) - n.z * Math.sin(globeRotX);
        let z1 = n.y * Math.sin(globeRotX) + n.z * Math.cos(globeRotX);
        
        let x2 = n.x * Math.cos(globeRotY) + z1 * Math.sin(globeRotY);
        let z2 = -n.x * Math.sin(globeRotY) + z1 * Math.cos(globeRotY);

        projectedNodes.push({
          x: cx + x2 * globeRadius,
          y: cy + y1 * globeRadius,
          z: z2,
          origX: x2,
          origY: y1
        });
      });

      projectedNodes.sort((a, b) => a.z - b.z);

      // Globe node connections
      ctx.lineWidth = 0.5;
      for (let i = 0; i < projectedNodes.length; i++) {
        for (let j = i + 1; j < projectedNodes.length; j++) {
          const p1 = projectedNodes[i];
          const p2 = projectedNodes[j];
          const dist2 = Math.pow(p1.origX - p2.origX, 2) + Math.pow(p1.origY - p2.origY, 2) + Math.pow(p1.z - p2.z, 2);
          
          if (dist2 < 0.08) {
            const alpha = (1 - dist2 / 0.08) * Math.max(0.05, (p1.z + 1) / 2) * 0.4;
            if (alpha > 0) {
              ctx.strokeStyle = `rgba(0, 229, 255, ${alpha})`;
              ctx.beginPath();
              ctx.moveTo(p1.x, p1.y);
              ctx.lineTo(p2.x, p2.y);
              ctx.stroke();
            }
          }
        }
      }

      // Globe points
      projectedNodes.forEach(p => {
        const alpha = Math.max(0.1, (p.z + 1) / 2);
        ctx.fillStyle = `rgba(255, 255, 255, ${alpha * 0.8})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1, 0, Math.PI * 2);
        ctx.fill();
        
        // Random bright pulses
        if (p.z > 0.8 && Math.random() > 0.98) {
          ctx.fillStyle = '#00E5FF';
          ctx.shadowBlur = 8;
          ctx.shadowColor = '#00E5FF';
          ctx.beginPath();
          ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      // Central Radar Sweep Cone
      const sweepAngle = (time * 2) % (Math.PI * 2);
      const sweepGrad = ctx.createConicGradient(sweepAngle, cx, cy);
      sweepGrad.addColorStop(0, 'rgba(0, 229, 255, 0)');
      sweepGrad.addColorStop(0.8, 'rgba(0, 229, 255, 0.02)');
      sweepGrad.addColorStop(1, 'rgba(0, 229, 255, 0.15)');
      
      ctx.fillStyle = sweepGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, globeRadius + 10, 0, Math.PI * 2);
      ctx.fill();

      // Sweep leading edge
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.8)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(sweepAngle) * (globeRadius + 10), cy + Math.sin(sweepAngle) * (globeRadius + 10));
      ctx.stroke();

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => cancelAnimationFrame(animationFrameId);
  }, []);

  return <canvas ref={canvasRef} style={{ width: 600, height: 600 }} className="absolute inset-0 z-10 pointer-events-none mix-blend-screen" />;
}

function JarvisCore({ onClick }: { onClick: () => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = canvas.width = 400;
    let height = canvas.height = 400;

    const particles: any[] = [];

    // Inner Core
    for (let i = 0; i < 80; i++) {
      const phi = Math.acos(-1 + (2 * i) / 80);
      const theta = Math.sqrt(80 * Math.PI) * phi;
      particles.push({
        baseX: Math.cos(theta) * Math.sin(phi),
        baseY: Math.sin(theta) * Math.sin(phi),
        baseZ: Math.cos(phi),
        layer: 'inner',
        radius: 40
      });
    }

    // Outer Shell
    for (let i = 0; i < 200; i++) {
      const phi = Math.acos(-1 + (2 * i) / 200);
      const theta = Math.sqrt(200 * Math.PI) * phi;
      particles.push({
        baseX: Math.cos(theta) * Math.sin(phi),
        baseY: Math.sin(theta) * Math.sin(phi),
        baseZ: Math.cos(phi),
        layer: 'outer',
        radius: 130
      });
    }

    let time = 0;
    let mouse = { x: -1000, y: -1000, isHover: false };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
      mouse.isHover = true;
    };

    const handleMouseLeave = () => {
      mouse.isHover = false;
    };

    canvas.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('mouseleave', handleMouseLeave);

    const render = () => {
      time += 0.005;
      ctx.clearRect(0, 0, width, height);

      // Complex 3D Rotation
      const rotX = time * 0.4 + Math.sin(time * 0.5) * 0.2;
      const rotY = time * 0.8;
      const rotZ = Math.cos(time * 0.3) * 0.3;

      const projected = particles.map(p => {
        // Apply varying speeds based on layer
        const layerSpin = p.layer === 'inner' ? -time * 2 : 0;
        
        let bx = p.baseX;
        let by = p.baseY;
        let bz = p.baseZ;

        // Extra spin for inner core
        if (layerSpin) {
          const sz = bz;
          const sx = bx * Math.cos(layerSpin) - by * Math.sin(layerSpin);
          const sy = bx * Math.sin(layerSpin) + by * Math.cos(layerSpin);
          bx = sx; by = sy; bz = sz;
        }

        // Rotate X
        let y1 = by * Math.cos(rotX) - bz * Math.sin(rotX);
        let z1 = by * Math.sin(rotX) + bz * Math.cos(rotX);
        // Rotate Y
        let x2 = bx * Math.cos(rotY) + z1 * Math.sin(rotY);
        let z2 = -bx * Math.sin(rotY) + z1 * Math.cos(rotY);
        // Rotate Z
        let x3 = x2 * Math.cos(rotZ) - y1 * Math.sin(rotZ);
        let y3 = x2 * Math.sin(rotZ) + y1 * Math.cos(rotZ);

        // Interactive "Touch" effect (molecules repel from mouse)
        // Only outer shell repels strongly
        const r = p.radius + Math.sin(time * 4 + p.baseX * 5) * (p.layer === 'inner' ? 2 : 5);
        const screenX = width / 2 + x3 * r;
        const screenY = height / 2 + y3 * r;
        
        let dx = 0;
        let dy = 0;
        let scale = 1;

        if (mouse.isHover) {
          const distToMouse = Math.hypot(screenX - mouse.x, screenY - mouse.y);
          const repelRadius = p.layer === 'outer' ? 100 : 40;
          if (distToMouse < repelRadius) {
            const force = Math.pow((repelRadius - distToMouse) / repelRadius, 2);
            dx = ((screenX - mouse.x) / distToMouse) * force * (p.layer === 'outer' ? 40 : 10);
            dy = ((screenY - mouse.y) / distToMouse) * force * (p.layer === 'outer' ? 40 : 10);
            scale = 1 + force * 1.5;
          }
        }

        return {
          x: screenX + dx,
          y: screenY + dy,
          z: z2,
          scale: scale,
          layer: p.layer,
          r: r
        };
      });

      // Sort by Z to draw back-to-front
      projected.sort((a, b) => a.z - b.z);

      // Draw connections
      ctx.lineWidth = 0.5;
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const p1 = projected[i];
          const p2 = projected[j];

          // Only connect within the same layer
          if (p1.layer !== p2.layer) continue;
          
          const maxDist = p1.layer === 'inner' ? 400 : 3000;
          const d2 = Math.pow(p1.x - p2.x, 2) + Math.pow(p1.y - p2.y, 2) + Math.pow((p1.z - p2.z) * p1.r, 2);
          
          if (d2 < maxDist) {
            const alpha = (1 - d2 / maxDist) * (p1.z + 1) * (p1.layer === 'inner' ? 0.6 : 0.25); 
            if (alpha > 0) {
              ctx.strokeStyle = p1.layer === 'inner' ? `rgba(255, 255, 255, ${alpha})` : `rgba(0, 229, 255, ${alpha})`;
              ctx.beginPath();
              ctx.moveTo(p1.x, p1.y);
              ctx.lineTo(p2.x, p2.y);
              ctx.stroke();
            }
          }
        }
      }

      // Draw nodes
      projected.forEach(p => {
        const baseRadius = p.layer === 'inner' ? 2 : 1.5;
        const zScale = (p.z + 2) / 2; // 0.5 to 1.5
        const r = baseRadius * zScale * p.scale;
        
        const alpha = Math.max(0.1, (p.z + 1) / 2) * (p.layer === 'inner' ? 1 : 0.8);
        
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fillStyle = p.layer === 'inner' ? `rgba(255, 255, 255, ${alpha})` : `rgba(0, 229, 255, ${alpha})`;
        ctx.fill();
        
        // Glow for front particles or inner core
        if ((p.z > 0.5 && p.scale > 1.2) || p.layer === 'inner') {
          ctx.shadowBlur = p.layer === 'inner' ? 15 : 10;
          ctx.shadowColor = p.layer === 'inner' ? '#FFFFFF' : '#00E5FF';
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      canvas.removeEventListener('mousemove', handleMouseMove);
      canvas.removeEventListener('mouseleave', handleMouseLeave);
    };
  }, []);

  return (
    <div className="relative group cursor-pointer" onClick={onClick}>
      <div className="absolute inset-0 bg-neon-blue/20 rounded-full blur-[60px] group-hover:bg-neon-blue/40 transition-colors duration-700 pointer-events-none" />
      <canvas 
        ref={canvasRef} 
        style={{ width: 400, height: 400 }} 
        className="relative z-10"
      />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-center pointer-events-none">
        <div className="text-neon-blue font-bold tracking-[0.3em] text-xs opacity-0 group-hover:opacity-100 transition-opacity duration-500 drop-shadow-[0_0_8px_#00E5FF]">
          WAKE JARVIS
        </div>
      </div>
    </div>
  );
}

export function BootSequence({ onComplete }: BootSequenceProps) {
  const [stage, setStage] = useState<'idle' | 'booting' | 'complete'>('idle');
  const [text, setText] = useState('');
  const fullText = "WAKING OVERSEER AI...\nINITIALIZING AEGIS UPLINK...\nESTABLISHING ENCRYPTED HANDSHAKE...\nAEGIS TACTICAL SUBSYSTEMS ONLINE.";

  const startBoot = () => {
    setStage('booting');

    if ('speechSynthesis' in window) {
      const msg = new SpeechSynthesisUtterance("Welcome to Hex Sniff. Aegis systems online.");
      const voices = window.speechSynthesis.getVoices();
      const preferred = voices.find(v => v.name.includes('Google UK English Male') || v.name.includes('Daniel') || v.name.includes('David') || v.name.includes('Zira') || v.lang === 'en-GB');
      if (preferred) msg.voice = preferred;
      msg.rate = 1.0; 
      msg.pitch = 0.8; 
      window.speechSynthesis.speak(msg);
    }

    let i = 0;
    const interval = setInterval(() => {
      setText(fullText.substring(0, i));
      i += 2;
      if (i > fullText.length) {
        clearInterval(interval);
        setTimeout(() => {
          setStage('complete');
          setTimeout(onComplete, 800);
        }, 3000); // Wait an extra 2 seconds for the voice to complete
      }
    }, 30); // Slightly slower text to match voice pacing
  };

  useEffect(() => {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.getVoices();
    }
  }, []);

  return (
    <div className="fixed inset-0 z-[9999] bg-[#070B14] flex items-center justify-center overflow-hidden font-sans">
      
      {/* Background Ambience */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(0,229,255,0.05)_0%,transparent_60%)] pointer-events-none" />

      <AnimatePresence mode="wait">
        {stage === 'idle' && (
          <m.div
            key="idle"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 1.5, filter: 'blur(20px)' }}
            transition={{ duration: 0.8, ease: [0.32, 0.72, 0, 1] }}
            className="flex flex-col items-center justify-center z-10"
          >
            <JarvisCore onClick={startBoot} />
            <div className="mt-8 text-text-muted text-[10px] font-mono tracking-widest uppercase opacity-50">
              System Standby — Click Core to Initialize
            </div>
          </m.div>
        )}

        {stage === 'booting' && (
          <m.div 
            key="booting"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, scale: 1.5, filter: 'blur(20px)' }}
            transition={{ duration: 0.8, ease: [0.32, 0.72, 0, 1] }}
            className="relative w-[600px] h-[600px] flex items-center justify-center isolate"
          >
            {/* The 3D Advanced Booting Visualizer */}
            <BootingVisualizer />

            {/* Terminal Output Overlay */}
            <div className="absolute bottom-10 left-1/2 -translate-x-1/2 w-full max-w-[600px] text-center z-20">
              <pre className="text-white text-xs leading-relaxed whitespace-pre-wrap font-mono tracking-widest opacity-80 drop-shadow-md bg-black/20 p-4 rounded-xl border border-white/5 backdrop-blur-sm">
                {text}
                <span className="animate-pulse text-[#00E5FF]">_</span>
              </pre>
            </div>
          </m.div>
        )}
      </AnimatePresence>
    </div>
  );
}
