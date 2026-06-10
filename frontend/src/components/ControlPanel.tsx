import React, { useRef, useState } from "react";
import { Play, Square, Activity, Upload, AlertCircle } from "lucide-react";

interface NetworkInterface {
  name: string;
  description: string;
  ip: string;
  capture_capable?: boolean;
  guid?: string;
  npcap_available?: boolean;
}

interface ControlPanelProps {
  interfaces: NetworkInterface[];
  mode: "live" | "sim" | null;
  activeInterface: string;
  onChangeInterface: (name: string) => void;
  onStartLive: () => void;
  onStartSim: () => void;
  onStop: () => void;
  onPcapUploaded: (data: any) => void;
}

export const ControlPanel: React.FC<ControlPanelProps> = ({
  interfaces,
  mode,
  activeInterface,
  onChangeInterface,
  onStartLive,
  onStartSim,
  onStop,
  onPcapUploaded,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      await handlePcapFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      await handlePcapFile(e.target.files[0]);
    }
  };

  const handlePcapFile = async (file: File) => {
    if (!file.name.endsWith(".pcap") && !file.name.endsWith(".pcapng")) {
      setUploadError("Only .pcap or .pcapng files are supported.");
      return;
    }

    setUploadError(null);
    setUploading(true);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("http://127.0.0.1:8000/api/upload-pcap", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Failed to parse PCAP file.");
      }

      const result = await response.json();
      onPcapUploaded(result);
    } catch (err: any) {
      setUploadError(err.message || "Network error uploading PCAP.");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="glass-card control-sidebar">
      <div className="glass-card-header">
        <div className="glass-card-title">
          <Activity size={16} />
          <span>Capture Controls</span>
        </div>
      </div>
      <div className="glass-card-content control-section">
        {/* Network Interface selection */}
        <div className="control-section">
          <label className="control-label">Capture Interface</label>
          <select
            className="select-dropdown"
            value={activeInterface}
            onChange={(e) => onChangeInterface(e.target.value)}
            disabled={mode !== null}
          >
            {interfaces.map((iface) => (
              <option key={iface.name} value={iface.name}>
                {iface.description}
              </option>
            ))}
          </select>
        </div>

        {/* Action Buttons */}
        <div className="control-section" style={{ marginTop: "8px", gap: "8px" }}>
          {mode === null ? (
            <>
              <button className="action-btn btn-primary" onClick={onStartLive}>
                <Play size={14} />
                <span>Start Sniffing</span>
              </button>
              
              <button className="action-btn btn-outline-purple" onClick={onStartSim}>
                <Activity size={14} />
                <span>Replay Local PCAP</span>
              </button>
            </>
          ) : (
            <button className="action-btn btn-danger" onClick={onStop}>
              <Square size={14} />
              <span>Stop Capture</span>
            </button>
          )}
        </div>

        <hr style={{ border: "0", borderTop: "1px solid var(--border-color)", margin: "12px 0" }} />

        {/* PCAP Uploader */}
        <div className="control-section">
          <label className="control-label">Offline Analysis</label>
          <div
            className={`file-upload-zone ${dragActive ? "drag-active" : ""}`}
            onDragEnter={handleDrag}
            onDragOver={handleDrag}
            onDragLeave={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              style={{ display: "none" }}
              accept=".pcap,.pcapng"
              disabled={mode !== null}
            />
            <Upload size={20} className="file-upload-icon" />
            <div className="file-upload-text">
              {uploading ? (
                <span>Parsing PCAP File...</span>
              ) : (
                <>
                  Drag & drop PCAP or <span style={{ textDecoration: "underline" }}>browse</span>
                </>
              )}
            </div>
          </div>
          {uploadError && (
            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--accent-red)", fontSize: "11px", marginTop: "4px" }}>
              <AlertCircle size={12} />
              <span>{uploadError}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
