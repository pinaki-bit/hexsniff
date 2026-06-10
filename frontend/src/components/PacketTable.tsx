import React, { useEffect, useRef } from "react";
import { Terminal, ShieldAlert } from "lucide-react";

interface Alert {
  id: string;
  severity: "High" | "Medium" | "Low";
  category: string;
  message: string;
}

interface PacketData {
  id: string;
  timestamp: number;
  length: number;
  proto: string;
  src_ip: string;
  dst_ip: string;
  src_mac: string;
  dst_mac: string;
  src_port: number | null;
  dst_port: number | null;
  tcp_flags: string;
  dns_query: string | null;
  summary: string;
  hex_dump: string;
  ascii_dump: string;
  alerts: Alert[];
}

interface PacketTableProps {
  packets: PacketData[];
  selectedPacketId: string | null;
  onSelectPacket: (packet: PacketData) => void;
  autoScroll: boolean;
}

export const PacketTable: React.FC<PacketTableProps> = ({
  packets,
  selectedPacketId,
  onSelectPacket,
  autoScroll,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [packets, autoScroll]);

  // Format timestamp (float epoch) to HH:MM:SS.mmm
  const formatTime = (epoch: number) => {
    const date = new Date(epoch * 1000);
    const hours = String(date.getHours()).padStart(2, "0");
    const minutes = String(date.getMinutes()).padStart(2, "0");
    const seconds = String(date.getSeconds()).padStart(2, "0");
    const ms = String(date.getMilliseconds()).padStart(3, "0");
    return `${hours}:${minutes}:${seconds}.${ms}`;
  };

  const getProtoClass = (proto: string) => {
    const p = proto.toLowerCase();
    if (p === "tcp") return "proto-badge tcp";
    if (p === "udp") return "proto-badge udp";
    if (p === "dns") return "proto-badge dns";
    if (p === "icmp") return "proto-badge icmp";
    if (p === "arp") return "proto-badge arp";
    return "proto-badge other";
  };

  return (
    <div className="glass-card" style={{ height: "100%" }}>
      <div className="glass-card-header">
        <div className="glass-card-title">
          <Terminal size={16} />
          <span>Live Packet Stream</span>
        </div>
        <span style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>
          Showing latest {packets.length} packets
        </span>
      </div>
      <div className="table-scroll-container" ref={containerRef}>
        {packets.length === 0 ? (
          <div className="empty-state">
            <Terminal size={36} />
            <p>Awaiting network activity. Start sniffing or lab validation to view packets.</p>
          </div>
        ) : (
          <table className="packet-table">
            <thead>
              <tr>
                <th style={{ width: "90px" }}>Time</th>
                <th style={{ width: "130px" }}>Source IP</th>
                <th style={{ width: "130px" }}>Destination IP</th>
                <th style={{ width: "70px" }}>Proto</th>
                <th style={{ width: "70px" }}>Length</th>
                <th>Info</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((pkt) => {
                const hasAlert = pkt.alerts && pkt.alerts.length > 0;
                const isSelected = pkt.id === selectedPacketId;
                
                return (
                  <tr
                    key={pkt.id}
                    className={`packet-row ${isSelected ? "selected" : ""} ${hasAlert ? "alerted" : ""}`}
                    onClick={() => onSelectPacket(pkt)}
                  >
                    <td>{formatTime(pkt.timestamp)}</td>
                    <td title={pkt.src_ip}>{pkt.src_ip}</td>
                    <td title={pkt.dst_ip}>{pkt.dst_ip}</td>
                    <td>
                      <span className={getProtoClass(pkt.proto)}>{pkt.proto}</span>
                    </td>
                    <td>{pkt.length} B</td>
                    <td style={{ display: "flex", alignItems: "center", gap: "8px", borderBottom: "none" }}>
                      {hasAlert && (
                        <ShieldAlert size={14} style={{ color: "var(--accent-red)", flexShrink: 0 }} />
                      )}
                      <span style={{ textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap", width: "100%" }} title={pkt.summary}>
                        {pkt.summary}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
