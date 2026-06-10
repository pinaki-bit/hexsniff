import React from "react";
import { BarChart3 } from "lucide-react";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import type { ChartOptions } from "chart.js";
import { Line, Doughnut } from "react-chartjs-2";

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler
);

interface VisualsProps {
  protocolCounts: {
    TCP: number;
    UDP: number;
    DNS: number;
    ICMP: number;
    ARP: number;
    Other: number;
  };
  timelineData: {
    labels: string[];
    counts: number[];
  };
}

export const Visuals: React.FC<VisualsProps> = ({ protocolCounts, timelineData }) => {
  // Protocol Doughnut configuration
  const totalProtocols = Object.values(protocolCounts).reduce((a, b) => a + b, 0);
  
  const doughnutData = {
    labels: ["TCP", "UDP", "DNS", "ICMP", "ARP", "Other"],
    datasets: [
      {
        data: [
          protocolCounts.TCP,
          protocolCounts.UDP,
          protocolCounts.DNS,
          protocolCounts.ICMP,
          protocolCounts.ARP,
          protocolCounts.Other,
        ],
        backgroundColor: [
          "rgba(59, 130, 246, 0.6)",   // TCP - blue
          "rgba(16, 185, 129, 0.6)",   // UDP - green
          "rgba(139, 92, 246, 0.6)",   // DNS - purple
          "rgba(236, 72, 153, 0.6)",   // ICMP - pink
          "rgba(245, 158, 11, 0.6)",   // ARP - amber
          "rgba(107, 114, 128, 0.6)",  // Other - gray
        ],
        borderColor: [
          "#3b82f6",
          "#10b981",
          "#8b5cf6",
          "#ec4899",
          "#f59e0b",
          "#6b7280",
        ],
        borderWidth: 1.5,
      },
    ],
  };

  const doughnutOptions: ChartOptions<"doughnut"> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "right",
        labels: {
          color: "#9ca3af",
          font: {
            family: "Outfit",
            size: 11,
          },
          boxWidth: 12,
        },
      },
      tooltip: {
        titleFont: { family: "Outfit" },
        bodyFont: { family: "Outfit" },
      },
    },
    cutout: "65%",
  };

  // Traffic rate line chart configuration
  const lineData = {
    labels: timelineData.labels,
    datasets: [
      {
        fill: true,
        label: "Packets / sec",
        data: timelineData.counts,
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59, 130, 246, 0.08)",
        borderWidth: 2,
        pointBackgroundColor: "#3b82f6",
        pointRadius: 1.5,
        pointHoverRadius: 4,
        tension: 0.3,
      },
    ],
  };

  const lineOptions: ChartOptions<"line"> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        titleFont: { family: "Outfit" },
        bodyFont: { family: "Outfit" },
      },
    },
    scales: {
      x: {
        grid: {
          color: "rgba(255, 255, 255, 0.02)",
        },
        ticks: {
          color: "#6b7280",
          font: {
            family: "JetBrains Mono",
            size: 9,
          },
          maxTicksLimit: 8,
        },
      },
      y: {
        grid: {
          color: "rgba(255, 255, 255, 0.03)",
        },
        ticks: {
          color: "#6b7280",
          font: {
            family: "JetBrains Mono",
            size: 9,
          },
          precision: 0,
        },
        min: 0,
      },
    },
  };

  return (
    <div className="glass-card">
      <div className="glass-card-header">
        <div className="glass-card-title">
          <BarChart3 size={16} />
          <span>Traffic Diagnostics</span>
        </div>
      </div>
      <div className="glass-card-content visuals-container" style={{ padding: "16px" }}>
        {/* Timeline Line Chart */}
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <span className="control-label" style={{ fontSize: "11px" }}>Traffic Volume (Packets/Sec)</span>
          <div className="chart-wrapper" style={{ height: "150px" }}>
            {timelineData.counts.length === 0 ? (
              <span style={{ color: "var(--text-muted)", fontSize: "12px" }}>No chart data</span>
            ) : (
              <Line data={lineData} options={lineOptions} />
            )}
          </div>
        </div>

        {/* Protocol Doughnut Chart */}
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <span className="control-label" style={{ fontSize: "11px" }}>Protocol Ratio</span>
          <div className="chart-wrapper" style={{ height: "150px" }}>
            {totalProtocols === 0 ? (
              <span style={{ color: "var(--text-muted)", fontSize: "12px" }}>No traffic recorded</span>
            ) : (
              <Doughnut data={doughnutData} options={doughnutOptions} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
