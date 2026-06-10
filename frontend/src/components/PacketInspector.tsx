import React, { useState } from "react";
import { Terminal, Database } from "lucide-react";

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

interface PacketInspectorProps {
  packet: PacketData | null;
}

export const PacketInspector: React.FC<PacketInspectorProps> = ({ packet }) => {
  const [activeTab, setActiveTab] = useState<"headers" | "hex" | "ascii">("headers");

  if (!packet) {
    return (
      <div className="glass-card" style={{ height: "100%" }}>
        <div className="glass-card-header">
          <div className="glass-card-title">
            <Database size={16} />
            <span>Packet Inspector</span>
          </div>
        </div>
        <div className="empty-state">
          <Database size={36} />
          <p>Select a packet from the stream to inspect its headers and payload.</p>
        </div>
      </div>
    );
  }

  const hasPayload = packet.hex_dump || packet.ascii_dump;

  return (
    <div className="glass-card" style={{ height: "100%" }}>
      <div className="glass-card-header">
        <div className="glass-card-title">
          <Database size={16} />
          <span>Packet Inspector // {packet.id.toUpperCase()}</span>
        </div>
        <span className="proto-badge tcp" style={{ fontSize: "10px" }}>
          {packet.proto}
        </span>
      </div>
      <div className="glass-card-content" style={{ display: "flex", flexDirection: "column" }}>
        {/* Navigation Tabs */}
        <div className="inspector-tabs">
          <div
            className={`inspector-tab ${activeTab === "headers" ? "active" : ""}`}
            onClick={() => setActiveTab("headers")}
          >
            Decoded Headers
          </div>
          <div
            className={`inspector-tab ${activeTab === "hex" ? "active" : ""}`}
            onClick={() => setActiveTab("hex")}
          >
            Hex Dump
          </div>
          <div
            className={`inspector-tab ${activeTab === "ascii" ? "active" : ""}`}
            onClick={() => setActiveTab("ascii")}
          >
            ASCII View
          </div>
        </div>

        {/* Tab Contents */}
        {activeTab === "headers" && (
          <div className="packet-header-tree">
            {/* Ethernet Layer */}
            <div className="tree-node">
              <div className="tree-node-title">Frame Link (Ethernet II)</div>
              <div className="tree-node-details">
                <span className="tree-node-key">Source MAC:</span>
                <span className="tree-node-val">{packet.src_mac}</span>
                <span className="tree-node-key">Destination MAC:</span>
                <span className="tree-node-val">{packet.dst_mac}</span>
                <span className="tree-node-key">Frame Length:</span>
                <span className="tree-node-val">{packet.length} bytes</span>
              </div>
            </div>

            {/* Network Layer IP */}
            {(packet.proto === "TCP" || packet.proto === "UDP" || packet.proto === "DNS" || packet.proto === "ICMP" || packet.proto.startsWith("IPv")) && (
              <div className="tree-node">
                <div className="tree-node-title">Internet Protocol (IPv4/IPv6)</div>
                <div className="tree-node-details">
                  <span className="tree-node-key">Source IP:</span>
                  <span className="tree-node-val">{packet.src_ip}</span>
                  <span className="tree-node-key">Destination IP:</span>
                  <span className="tree-node-val">{packet.dst_ip}</span>
                  <span className="tree-node-key">Protocol:</span>
                  <span className="tree-node-val">{packet.proto}</span>
                </div>
              </div>
            )}

            {/* Transport Layer */}
            {packet.proto === "TCP" && (
              <div className="tree-node">
                <div className="tree-node-title">Transmission Control Protocol (TCP)</div>
                <div className="tree-node-details">
                  <span className="tree-node-key">Source Port:</span>
                  <span className="tree-node-val">{packet.src_port}</span>
                  <span className="tree-node-key">Destination Port:</span>
                  <span className="tree-node-val">{packet.dst_port}</span>
                  <span className="tree-node-key">TCP Flags:</span>
                  <span className="tree-node-val">{packet.tcp_flags || "None"}</span>
                </div>
              </div>
            )}

            {packet.proto === "UDP" && (
              <div className="tree-node">
                <div className="tree-node-title">User Datagram Protocol (UDP)</div>
                <div className="tree-node-details">
                  <span className="tree-node-key">Source Port:</span>
                  <span className="tree-node-val">{packet.src_port}</span>
                  <span className="tree-node-key">Destination Port:</span>
                  <span className="tree-node-val">{packet.dst_port}</span>
                </div>
              </div>
            )}

            {/* Application Layer Specifics */}
            {packet.proto === "DNS" && (
              <div className="tree-node">
                <div className="tree-node-title">Domain Name System (DNS Query)</div>
                <div className="tree-node-details">
                  <span className="tree-node-key">Query Domain:</span>
                  <span className="tree-node-val">{packet.dns_query || "N/A"}</span>
                  <span className="tree-node-key">Source Port:</span>
                  <span className="tree-node-val">{packet.src_port}</span>
                  <span className="tree-node-key">Destination Port:</span>
                  <span className="tree-node-val">{packet.dst_port}</span>
                </div>
              </div>
            )}

            {/* Raw Summary */}
            <div className="tree-node">
              <div className="tree-node-title">Info Summary</div>
              <div style={{ color: "var(--text-secondary)", fontStyle: "italic" }}>
                {packet.summary}
              </div>
            </div>
          </div>
        )}

        {activeTab === "hex" && (
          hasPayload ? (
            <div className="raw-dump-container">
              <div className="hex-column">{packet.hex_dump}</div>
              <div className="ascii-column" style={{ userSelect: "none" }}>{packet.ascii_dump}</div>
            </div>
          ) : (
            <div className="empty-state">
              <Terminal size={24} />
              <p style={{ marginTop: "8px" }}>No raw payload available for this packet (Headers only).</p>
            </div>
          )
        )}

        {activeTab === "ascii" && (
          hasPayload ? (
            <pre style={{
              fontFamily: "var(--font-mono)",
              fontSize: "12px",
              background: "rgba(0, 0, 0, 0.2)",
              padding: "12px",
              borderRadius: "6px",
              overflow: "auto",
              height: "100%",
              whiteSpace: "pre-wrap",
              color: "#34d399",
              border: "1px solid rgba(255, 255, 255, 0.02)"
            }}>
              {packet.ascii_dump}
            </pre>
          ) : (
            <div className="empty-state">
              <Terminal size={24} />
              <p style={{ marginTop: "8px" }}>No raw payload available for this packet.</p>
            </div>
          )
        )}
      </div>
    </div>
  );
};
