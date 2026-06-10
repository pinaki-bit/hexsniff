import { useState, useEffect, useRef } from 'react';
import { Brain, Cpu, Sparkles, RefreshCw, ShieldAlert, ChevronRight, Send, User } from 'lucide-react';
import { useStore } from '../store';
import { m, AnimatePresence } from 'framer-motion';

// Markdown Renderer
function renderMarkdown(md: string) {
  if (!md) return null;
  const lines = md.split('\n');
  const elements: React.ReactNode[] = [];
  
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('###')) {
      elements.push(<h4 key={index} className="text-sm font-bold text-white mt-4 mb-2 flex items-center gap-2"><ChevronRight size={14} className="text-neon-blue"/> {trimmed.slice(3).trim()}</h4>);
    } else if (trimmed.startsWith('##')) {
      elements.push(<h3 key={index} className="text-sm font-bold text-neon-blue mt-5 mb-3 border-b border-white/5 pb-2 uppercase tracking-widest">{trimmed.slice(2).trim()}</h3>);
    } else if (trimmed.startsWith('#')) {
      elements.push(<h2 key={index} className="text-base font-bold text-white mt-2 mb-4">{trimmed.slice(1).trim()}</h2>);
    } else if (trimmed.startsWith('-') || trimmed.startsWith('*')) {
      const bulletText = trimmed.slice(1).trim();
      const boldMatch = bulletText.match(/^\*\*(.*?)\*\*(.*)/);
      if (boldMatch) {
        elements.push(
          <li key={index} className="ml-2 text-xs mb-1.5 text-text-muted flex items-start">
            <span className="w-1 h-1 rounded-full bg-neon-blue shrink-0 mt-1.5 mr-2 shadow-glow-blue" />
            <span><strong className="text-white font-semibold">{boldMatch[1]}</strong>{boldMatch[2]}</span>
          </li>
        );
      } else {
        elements.push(
          <li key={index} className="ml-2 text-xs mb-1.5 text-text-muted flex items-start">
            <span className="w-1 h-1 rounded-full bg-border-subtle shrink-0 mt-1.5 mr-2" />
            <span>{bulletText}</span>
          </li>
        );
      }
    } else if (trimmed.startsWith('|')) {
       // Super hacky table render for markdown tables to avoid massive parsing logic
       elements.push(<div key={index} className="font-mono text-[9px] whitespace-pre text-text-muted overflow-x-auto">{trimmed}</div>);
    } else if (trimmed) {
      const parts = trimmed.split('**');
      if (parts.length > 1) {
        elements.push(
          <p key={index} className="text-xs leading-relaxed my-2 text-text-muted">
            {parts.map((part, pi) => pi % 2 === 1 ? <strong key={pi} className="text-white font-semibold">{part}</strong> : part)}
          </p>
        );
      } else {
        elements.push(<p key={index} className="text-xs leading-relaxed my-2 text-text-muted">{trimmed}</p>);
      }
    }
  });

  return <div className="flex flex-col gap-1 font-sans">{elements}</div>;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'ai';
  content: string;
  timestamp: Date;
  source?: string;
  isError?: boolean;
}

export function AIAnalyst() {
  const { packets, alerts } = useStore();
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [query, setQuery] = useState('');
  const chatEndRef = useRef<HTMLDivElement>(null);

  const requestAnalysis = async (queryStr?: string, clearHistory: boolean = false) => {
    if (!queryStr && messages.length > 0 && !clearHistory) return;
    
    setLoading(true);
    
    // Optimistic UI update
    const baseMessages = clearHistory ? [] : [...messages];
    const newMessages = [...baseMessages];
    if (queryStr) {
      newMessages.push({ id: crypto.randomUUID(), role: 'user', content: queryStr, timestamp: new Date() });
      setMessages(newMessages);
    }
    
    try {
      // Send the base history to the backend (WITHOUT the new query, because the backend will append the query to the history itself)
      const historyPayload = baseMessages.map(m => ({ role: m.role, content: m.content }));
      
      const res = await fetch('http://127.0.0.1:8000/api/ai/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          query: queryStr || "Generate an initial Executive Summary of the global network state.", 
          history: historyPayload,
          context_refs: null // We will implement Context references next
        })
      });
      if (!res.ok) throw new Error('API failure');
      const data = await res.json();
      
      setMessages(prev => [...prev, { 
        id: crypto.randomUUID(), 
        role: 'ai', 
        content: data.analysis, 
        timestamp: new Date(),
        source: data.source
      }]);
    } catch (e) {
      setMessages(prev => [...prev, { 
        id: crypto.randomUUID(), 
        role: 'ai', 
        content: 'Uplink failed: Copilot Service unreachable. Verify OPENAI_API_KEY is set in backend and the API is reachable.', 
        timestamp: new Date(),
        isError: true
      }]);
    } finally {
      setLoading(false);
    }
  };

  // Initial Briefing auto-fetch
  useEffect(() => {
    if (packets.length > 0 && messages.length === 0 && !loading) {
      const timer = setTimeout(() => requestAnalysis(), 500);
      return () => clearTimeout(timer);
    }
  }, [packets, messages.length, loading]);

  // Scroll to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const securityMetrics = [
    { label: 'Active Alerts', val: alerts.length, color: alerts.length > 0 ? 'text-crimson text-glow-red' : 'text-neon-blue' },
    { label: 'Authentication Risks', val: alerts.filter(a => a.category.includes('Credential') || a.category.includes('Password')).length, color: 'text-amber text-glow-amber' },
    { label: 'Probing Scans', val: alerts.filter(a => a.category.includes('Scan')).length, color: 'text-amber' },
    { label: 'Total Packets', val: packets.length, color: 'text-white' }
  ];

  return (
    <m.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col lg:flex-row gap-6 h-full max-w-[1600px] mx-auto pb-6"
    >
      {/* ── Left Column: Operations Control ── */}
      <div className="flex flex-col gap-6 lg:w-[340px] shrink-0">
        
        {/* Intelligence Neural Core */}
        <div className="glass-panel rounded-2xl flex flex-col shadow-card overflow-hidden">
          <div className="px-5 py-4 border-b border-border-dim bg-surface-active/50 flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest">
            <Brain size={14} className="text-neon-blue" /> Overseer Neural Core
          </div>
          
          <div className="p-6 flex flex-col items-center gap-6 relative">
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,240,255,0.05)_0%,transparent_70%)] pointer-events-none" />
            
            <div className="relative flex items-center justify-center w-32 h-32">
              <m.svg className="absolute inset-0 w-full h-full opacity-40" viewBox="0 0 100 100" animate={{ rotateZ: 360 }} transition={{ duration: 20, repeat: Infinity, ease: "linear" }}>
                <circle cx="50" cy="50" r="48" fill="none" stroke="#00F0FF" strokeWidth="0.5" strokeDasharray="4 8" />
                <circle cx="50" cy="50" r="38" fill="none" stroke="#FFFFFF" strokeWidth="1" strokeDasharray="20 10 5 10" opacity="0.3" />
              </m.svg>
              {loading && (
                <m.svg className="absolute inset-0 w-full h-full mix-blend-screen" viewBox="0 0 100 100" animate={{ rotateZ: -360 }} transition={{ duration: 3, repeat: Infinity, ease: "linear" }}>
                  <circle cx="50" cy="50" r="44" fill="none" stroke="#00F0FF" strokeWidth="2" strokeDasharray="40 100" strokeLinecap="round" />
                </m.svg>
              )}
              <div className={`w-16 h-16 rounded-full border flex items-center justify-center backdrop-blur-md transition-all duration-500 z-10 ${loading ? 'bg-neon-blue/20 border-neon-blue shadow-glow-blue scale-110' : 'bg-void/80 border-border-dim'}`}>
                <Brain size={32} className={`${loading ? 'text-neon-blue animate-pulse' : 'text-text-muted'}`} />
              </div>
            </div>

            <m.button
              whileHover={{ scale: 1.02, backgroundColor: 'rgba(255,255,255,0.1)' }}
              whileTap={{ scale: 0.98 }}
              onClick={() => {
                requestAnalysis("Analyze the entire network environment and generate a comprehensive security briefing.", true);
              }}
              disabled={loading}
              className="w-full py-3 px-4 rounded-xl border border-border-dim bg-surface-hover text-xs font-bold uppercase tracking-widest text-white flex justify-center items-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed hover:border-border-bright z-10 shadow-card"
            >
              {loading ? <RefreshCw className="animate-spin text-neon-blue" size={14} /> : <Sparkles className="text-neon-blue" size={14} />}
              {loading ? 'Processing...' : 'New Investigation'}
            </m.button>
          </div>
        </div>

        {/* Subnet Risk Summary */}
        <div className="glass-panel rounded-2xl flex flex-col shadow-card overflow-hidden">
          <div className="px-5 py-4 border-b border-border-dim bg-surface-active/50 flex items-center gap-2 text-xs font-bold text-white uppercase tracking-widest">
            <Cpu size={14} className="text-neon-blue" /> Network Posture
          </div>
          <div className="p-2">
            {securityMetrics.map(({ label, val, color }) => (
              <div key={label} className="flex justify-between items-center px-4 py-3 border-b border-border-dim/50 last:border-0 hover:bg-surface-hover transition-colors rounded-xl">
                <span className="text-xs font-sans text-text-muted">{label}</span>
                <span className={`text-sm font-mono font-bold ${color}`}>{val}</span>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* ── Right Column: SOC Copilot Interface ── */}
      <div className="glass-panel rounded-2xl flex flex-col flex-1 shadow-card overflow-hidden min-h-[500px]">
        <div className="px-6 py-5 border-b border-border-dim bg-surface-active/50 flex items-center gap-3 shrink-0">
          <div className="w-8 h-8 rounded-full bg-neon-blue/10 border border-neon-blue/30 flex items-center justify-center shadow-glow-blue">
             <Brain size={16} className="text-neon-blue" />
          </div>
          <div>
            <span className="text-sm font-bold text-white tracking-widest uppercase">Overseer Copilot</span>
            <div className="text-[10px] text-text-muted font-mono mt-0.5">Enterprise DFIR Assistant</div>
          </div>
          {loading && (
            <span className="ml-auto flex items-center gap-2 text-[10px] font-mono text-neon-blue tracking-widest uppercase animate-pulse">
              <span className="w-1.5 h-1.5 bg-neon-blue rounded-full shadow-glow-blue" /> Synthesizing
            </span>
          )}
        </div>
        
        <div className="flex-1 overflow-y-auto custom-scrollbar p-6 bg-void/50 flex flex-col gap-6 relative">
          <AnimatePresence initial={false}>
            {messages.length === 0 && !loading && (
               <m.div 
                 initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                 className="absolute inset-0 flex flex-col items-center justify-center text-text-muted/50"
               >
                 <Brain size={64} className="mb-4 opacity-20" />
                 <p className="text-sm max-w-md text-center">Copilot is standing by. Awaiting network telemetry ingestion for initial briefing synthesis.</p>
               </m.div>
            )}

            {messages.map((msg) => (
              <m.div 
                key={msg.id}
                initial={{ opacity: 0, y: 10, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
                className={`flex gap-4 max-w-[85%] ${msg.role === 'user' ? 'ml-auto flex-row-reverse' : ''}`}
              >
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 border mt-1 shadow-card
                  ${msg.role === 'ai' ? (msg.isError ? 'bg-crimson/10 border-crimson/50 text-crimson shadow-glow-red' : 'bg-neon-blue/10 border-neon-blue/50 text-neon-blue shadow-glow-blue') : 'bg-white/10 border-white/20 text-white'}
                `}>
                  {msg.role === 'ai' ? (msg.isError ? <ShieldAlert size={14} /> : <Brain size={14} />) : <User size={14} />}
                </div>
                
                <div className={`flex flex-col gap-1 min-w-0 ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                  <div className="text-[10px] text-text-muted font-mono tracking-widest uppercase px-1">
                    {msg.role === 'ai' ? (msg.source ? `Overseer • ${msg.source}` : 'Overseer') : 'Analyst'} • {msg.timestamp.toLocaleTimeString()}
                  </div>
                  <div className={`p-5 rounded-2xl border backdrop-blur-xl shadow-card
                    ${msg.role === 'user' ? 'bg-white/10 border-white/10 text-white rounded-tr-sm' : msg.isError ? 'bg-crimson/10 border-crimson/30 rounded-tl-sm' : 'bg-surface border-border-dim rounded-tl-sm'}
                  `}>
                    {msg.role === 'user' ? (
                      <p className="text-sm font-sans text-white">{msg.content}</p>
                    ) : (
                      renderMarkdown(msg.content)
                    )}
                  </div>
                </div>
              </m.div>
            ))}

            {loading && (
              <m.div 
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: 0.9 }}
                className="flex gap-4 max-w-[85%]"
              >
                <div className="w-8 h-8 rounded-full bg-neon-blue/10 border border-neon-blue/50 text-neon-blue flex items-center justify-center shrink-0 mt-1 shadow-glow-blue animate-pulse">
                  <Brain size={14} />
                </div>
                <div className="p-5 rounded-2xl border backdrop-blur-xl bg-surface border-border-dim rounded-tl-sm shadow-card flex items-center gap-2">
                   <div className="w-1.5 h-1.5 bg-neon-blue rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                   <div className="w-1.5 h-1.5 bg-neon-blue rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                   <div className="w-1.5 h-1.5 bg-neon-blue rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
              </m.div>
            )}
          </AnimatePresence>
          <div ref={chatEndRef} />
        </div>

        {/* Interactive Query Input */}
        <div className="p-5 border-t border-border-dim bg-surface-active/50 flex gap-3 shrink-0">
          <input 
            value={query} 
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && query.trim() && !loading) { requestAnalysis(query); setQuery(''); } }}
            placeholder="Ask Copilot to investigate IPs, hunt threats, or summarize attack chains..."
            className="flex-1 bg-void/80 border border-border-dim text-sm rounded-xl px-5 py-4 outline-none text-white focus:border-neon-blue/50 transition-colors font-sans placeholder:text-text-muted/50 shadow-inner"
          />
          <button 
            className="bg-neon-blue/10 border border-neon-blue/30 text-neon-blue px-6 py-4 rounded-xl text-xs font-bold uppercase tracking-widest hover:bg-neon-blue/20 transition-all shadow-glow-blue disabled:opacity-30 disabled:shadow-none disabled:cursor-not-allowed flex items-center gap-3"
            onClick={() => { if (query.trim() && !loading) { requestAnalysis(query); setQuery(''); } }}
            disabled={loading || !query.trim() || packets.length === 0}
          >
            Transmit <Send size={14} />
          </button>
        </div>
      </div>

    </m.div>
  );
}
