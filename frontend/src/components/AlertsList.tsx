import React from "react";
import { ShieldAlert, AlertTriangle, Info } from "lucide-react";

interface Alert {
  id: string;
  severity: "High" | "Medium" | "Low";
  category: string;
  message: string;
  timestamp?: number;
  packetId?: string; // Links back to the packet
  mitre_technique?: string;
  mitre_tactic?: string;
  confidence?: number;
  evidence_packets?: number;
}

interface AlertsListProps {
  alerts: Alert[];
  onSelectPacketById: (id: string) => void;
}

export const AlertsList: React.FC<AlertsListProps> = ({ alerts, onSelectPacketById }) => {
  const getSeverityClass = (sev: string) => {
    return sev.toLowerCase() === "high" ? "alert-card high" : "alert-card medium";
  };

  const getIcon = (sev: string) => {
    return sev.toLowerCase() === "high" ? (
      <ShieldAlert className="alert-icon high" size={18} />
    ) : (
      <AlertTriangle className="alert-icon medium" size={18} />
    );
  };

  const formatTime = (epoch?: number) => {
    if (!epoch) return "";
    const date = new Date(epoch * 1000);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <div className="glass-card" style={{ height: "100%" }}>
      <div className="glass-card-header">
        <div className="glass-card-title" style={{ color: "var(--accent-red)" }}>
          <ShieldAlert size={16} />
          <span>Threat Detection Alerts</span>
        </div>
        <span style={{ fontSize: "11px", color: "var(--accent-red)", fontWeight: "bold" }}>
          {alerts.length} Flagged Events
        </span>
      </div>
      <div className="glass-card-content" style={{ padding: "12px 16px" }}>
        {alerts.length === 0 ? (
          <div className="empty-state">
            <Info size={32} />
            <p style={{ textAlign: "center", fontSize: "13px" }}>
              No threat signatures detected. System secure.
            </p>
          </div>
        ) : (
          alerts.map((alert) => (
            <div
              key={alert.id}
              className={getSeverityClass(alert.severity)}
              onClick={() => alert.packetId && onSelectPacketById(alert.packetId)}
              style={{ cursor: alert.packetId ? "pointer" : "default" }}
              title={alert.packetId ? "Click to view offending packet details" : ""}
            >
              {getIcon(alert.severity)}
              <div className="alert-body">
                <div className="alert-meta" style={{ marginBottom: 4 }}>
                  <span className={`alert-title ${alert.severity.toLowerCase()}`} style={{ fontWeight: 600 }}>
                    {alert.category}
                  </span>
                  <span className="alert-time">{formatTime(alert.timestamp)}</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                  {alert.message}
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                  {alert.mitre_tactic && (
                    <span style={{ fontSize: 10, background: 'rgba(56,139,253,0.1)', color: 'var(--accent-blue-bright)', padding: '2px 6px', borderRadius: 4 }}>
                      {alert.mitre_technique} - {alert.mitre_tactic}
                    </span>
                  )}
                  {alert.confidence !== undefined && (
                    <span style={{ fontSize: 10, background: 'rgba(239,68,68,0.1)', color: 'var(--accent-red-bright)', padding: '2px 6px', borderRadius: 4 }}>
                      {alert.confidence}% Confidence
                    </span>
                  )}
                  {alert.evidence_packets && (
                    <span style={{ fontSize: 10, background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)', padding: '2px 6px', borderRadius: 4 }}>
                      {alert.evidence_packets} Packets
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
