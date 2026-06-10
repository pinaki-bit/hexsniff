import { useState, useRef, useEffect } from 'react';
import { Bot, X, Send } from 'lucide-react';
import { useStore } from '../store';

interface Msg { role: 'user' | 'ai'; text: string; }

const generateFinding = (category: string, alert: any) => {
  if (!alert) return `No evidence found for ${category}.`;
  
  return `Observation:
${alert.category} detected

Evidence:
Source IP: ${alert.src_ip || 'Unknown'}
Destination IP: ${alert.dst_ip || 'Unknown'}
MITRE Technique: ${alert.mitre_technique || 'Unmapped'} (${alert.mitre_tactic || 'Unmapped'})
Evidence Packets: ${alert.evidence_packets || 1}
Confidence Score: ${alert.confidence || 50}%
Time: ${new Date(alert.timestamp * 1000 || Date.now()).toLocaleTimeString()}
Details: ${alert.message}

Impact:
${alert.severity === 'High' || alert.severity === 'Critical' ? 'Immediate threat to network availability or integrity.' : 'Reconnaissance or anomalous behavior detected.'}

Recommendation:
${alert.severity === 'High' ? 'Immediately block the source IP and investigate targeted services.' : 'Monitor source IP for further escalation.'}`;
};

function getAIResponse(input: string, state: any): string {
  const q = input.toLowerCase();
  
  if (q.includes('alert') || q.includes('threat')) {
    if (state.alerts.length === 0) return 'Observation:\nNo alerts detected in current traffic.\n\nEvidence:\n0 alerts in active state.\n\nImpact:\nNone.\n\nRecommendation:\nContinue monitoring.';
    const latest = state.alerts[state.alerts.length - 1];
    return generateFinding('latest threat', latest);
  }

  if (q.includes('syn flood')) {
    const alert = state.alerts.find((a: any) => a.category === 'SYN Flood DDoS');
    return generateFinding('SYN Flood', alert);
  }

  if (q.includes('port scan')) {
    const alert = state.alerts.find((a: any) => a.category === 'Port Scanning');
    return generateFinding('Port Scan', alert);
  }
  
  if (q.includes('sql') || q.includes('sqli') || q.includes('inject')) {
    const alert = state.alerts.find((a: any) => a.category === 'SQL Injection Attempt');
    return generateFinding('SQL Injection', alert);
  }

  if (q.includes('mitre')) {
    const mappedAlerts = state.alerts.filter((a: any) => a.mitre_technique);
    if (mappedAlerts.length === 0) return 'No MITRE ATT&CK techniques mapped in current traffic.';
    const uniqueMitre = [...new Set(mappedAlerts.map((a: any) => `${a.mitre_technique} (${a.mitre_tactic})`))];
    const maxConf = Math.max(...mappedAlerts.map((a: any) => a.confidence || 0));
    return `Observation:\nMITRE techniques detected in live traffic.\n\nEvidence:\nTechniques observed: ${uniqueMitre.join(', ')}\nMax Confidence: ${maxConf}%\n\nImpact:\nAdversary behavior aligned with known MITRE tactics.\n\nRecommendation:\nReview Threat Intelligence dashboard for detailed kill chain mapping.`;
  }

  if (q.includes('packet') || q.includes('stats') || q.includes('dns') || q.includes('tcp') || q.includes('udp')) {
    return `Observation:\nTraffic statistics analyzed.\n\nEvidence:\nTotal Packets: ${state.totalPackets}\nTCP: ${state.protocolCounts['TCP'] || 0}\nUDP: ${state.protocolCounts['UDP'] || 0}\nDNS: ${state.protocolCounts['DNS'] || 0}\n\nImpact:\nNormal network operations.\n\nRecommendation:\nNone.`;
  }

  return `Observation:\nQuery unrecognized or no specific evidence matches your query.\n\nEvidence:\nPackets: ${state.totalPackets}, Alerts: ${state.alerts.length}\n\nImpact:\nNone.\n\nRecommendation:\nAsk about specific threats (e.g., 'alerts', 'syn flood', 'port scan') or traffic stats.`;
}

export function AICopilot() {
  const [open, setOpen] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([
    { role: 'ai', text: 'Hello! I\'m HexSniff AI Copilot 🛡️. I can analyze your traffic, explain threats, and guide your investigation. How can I help?' }
  ]);
  const [input, setInput] = useState('');
  const [typing, setTyping] = useState(false);
  const state = useStore();
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [msgs]);

  const send = () => {
    if (!input.trim()) return;
    const userMsg = input.trim();
    setInput('');
    setMsgs(m => [...m, { role: 'user', text: userMsg }]);
    setTyping(true);

    setTimeout(() => {
      const reply = getAIResponse(userMsg, state);
      setTyping(false);
      setMsgs(m => [...m, { role: 'ai', text: reply }]);
    }, 600 + Math.random() * 400);
  };

  return (
    <div className="chat-bubble">
      {open && (
        <div className="chat-panel animate-up">
          <div className="chat-header">
            <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'var(--accent-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Bot size={16} color="white" />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700 }}>HexSniff AI</div>
              <div style={{ fontSize: 10, color: 'var(--accent-green-bright)' }}>● Online</div>
            </div>
            <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }} onClick={() => setOpen(false)}>
              <X size={13} />
            </button>
          </div>

          <div className="chat-messages">
            {msgs.map((m, i) => (
              <div key={i} className={`chat-msg ${m.role}`} style={{ whiteSpace: 'pre-wrap' }}>{m.text}</div>
            ))}
            {typing && (
              <div className="chat-msg ai" style={{ display: 'flex', gap: 4, alignItems: 'center', padding: '10px 14px' }}>
                {[0, 0.2, 0.4].map((d, i) => (
                  <span key={i} style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-blue)', animation: `blink 1.2s ${d}s infinite`, display: 'block' }} />
                ))}
              </div>
            )}
            <div ref={endRef} />
          </div>

          {/* Quick prompts */}
          <div style={{ padding: '6px 10px', borderTop: '1px solid var(--border-dim)', display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {['What are my threats?', 'Explain SYN flood', 'DNS stats'].map(q => (
              <button key={q}
                onClick={() => { setInput(q); }}
                style={{ fontSize: 10, padding: '3px 8px', borderRadius: 10, background: 'rgba(56,139,253,0.1)', border: '1px solid rgba(56,139,253,0.2)', color: 'var(--accent-blue-bright)', cursor: 'pointer' }}>
                {q}
              </button>
            ))}
          </div>

          <div className="chat-input-row">
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && send()}
              placeholder="Ask about threats, protocols…"
            />
            <button className="btn btn-primary btn-sm" onClick={send}><Send size={12} /></button>
          </div>
        </div>
      )}

      <button className="chat-toggle-btn" onClick={() => setOpen(!open)}>
        {open ? <X size={20} /> : <Bot size={20} />}
      </button>
    </div>
  );
}
