# EXPORT PIPELINE AUDIT

## Trace:
`store.ts` → `Reports.tsx` → Export Formats (PDF, CSV, JSON)

## Where data is lost:

1. **`store.ts` Context:**
   The live session `PacketStore` parses `alerts` on-the-fly inside `addPackets`. When a packet matching an IOC or IDS rule is processed, it aggregates incidents by category/src/dst. It assigns `threat_score`, `risk_level`, `evidence_packets`, `ioc_hit`, `ioc_id`, etc. This means `store.ts` correctly maintains the data.

2. **`Reports.tsx` - CSV Export (`exportCSV`):**
   The CSV export iterates through `packets` instead of `alerts`. The headers exported are:
   `['ID', 'Timestamp', 'Protocol', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Length', 'Alerts', 'Summary']`
   **Data Lost:** It drops the alert objects entirely, exporting only a packet-level count `(p.alerts || []).length`. Threat Score, Evidence Packets, and IOC logic is completely skipped.

3. **`Reports.tsx` - PDF Export (`exportPDF`):**
   The PDF iterates through the `alerts` array, but manually picks the properties to render.
   ```javascript
   doc.text('Category', 18, y + 5);
   doc.text('Sev', 75, y + 5);
   doc.text('Technique', 90, y + 5);
   doc.text('Tactic', 125, y + 5);
   doc.text('Conf%', 165, y + 5);
   ```
   **Data Lost:** `threat_score`, `risk_level`, `evidence_packets`, and `ioc_hit/ioc_value` are not drawn onto the PDF canvas. Furthermore, it lacks the required structured summaries (Threat Score Summary, Evidence Statistics, IOC Summary).

4. **`Reports.tsx` - JSON Export (`exportJSON`):**
   The JSON export natively stringifies the entire `store.ts` state.
   ```javascript
   const data = { exportedAt: ..., summary: {...}, packets, alerts };
   ```
   **Data Preserved:** JSON correctly preserves all Phase 4 fields because they exist directly on the `Alert` interface in `store.ts`.

5. **`DetectionValidationLab.tsx` Export:**
   - JSON export stringifies the entire `ValidationSession`, which includes `threat_score`, `ioc_hits`, etc.
   - CSV export outputs: `["Session_ID", "PCAP_File", "Timestamp", "Alert_Category", "Risk_Level", "Threat_Score", "Src_IP", "Dst_IP", "Evidence_Count", "IOC_Hit", "IOC_Value", "MITRE"]`. This correctly fulfills requirements!
   - PDF export (`window.print()`) outputs a basic table containing `Risk Level`, `Score`, `Category`, `IOC Value`, `Evidence`. It has what's needed.

## Conclusion:
The primary failure point is **`Reports.tsx`**. The live session reporting logic must be refactored to explicitly render Phase 4 alert properties in CSV and PDF formats. JSON and Validation Lab exports are behaving as intended.
