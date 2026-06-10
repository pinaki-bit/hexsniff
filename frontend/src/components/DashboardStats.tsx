import React from "react";
import { Shield, AlertTriangle, Activity, Database } from "lucide-react";

interface DashboardStatsProps {
  totalPackets: number;
  totalAlerts: number;
  packetRate: number;
  dataRate: number; // in KB/s
}

export const DashboardStats: React.FC<DashboardStatsProps> = ({
  totalPackets,
  totalAlerts,
  packetRate,
  dataRate,
}) => {
  return (
    <div className="stats-grid">
      {/* Total Packets Card */}
      <div className="stat-box">
        <div className="stat-icon-wrapper blue">
          <Shield size={20} />
        </div>
        <div className="stat-info">
          <span className="stat-label">Total Packets</span>
          <span className="stat-val">{totalPackets.toLocaleString()}</span>
        </div>
      </div>

      {/* Security Alerts Card */}
      <div className={`stat-box ${totalAlerts > 0 ? "pulse-alert-high" : ""}`} style={totalAlerts > 0 ? { borderColor: "rgba(239, 68, 68, 0.4)", background: "rgba(239, 68, 68, 0.08)" } : {}}>
        <div className={`stat-icon-wrapper ${totalAlerts > 0 ? "red" : "green"}`}>
          <AlertTriangle size={20} />
        </div>
        <div className="stat-info">
          <span className="stat-label">IDS Alerts</span>
          <span className="stat-val" style={totalAlerts > 0 ? { color: "var(--accent-red)" } : {}}>
            {totalAlerts}
          </span>
        </div>
      </div>

      {/* Packet Rate Card */}
      <div className="stat-box">
        <div className="stat-icon-wrapper purple">
          <Activity size={20} />
        </div>
        <div className="stat-info">
          <span className="stat-label">Packet Rate</span>
          <span className="stat-val">{packetRate} pps</span>
        </div>
      </div>

      {/* Bandwidth Card */}
      <div className="stat-box">
        <div className="stat-icon-wrapper green">
          <Database size={20} />
        </div>
        <div className="stat-info">
          <span className="stat-label">Bandwidth</span>
          <span className="stat-val">{dataRate.toFixed(2)} KB/s</span>
        </div>
      </div>
    </div>
  );
};
