# PHASE 5 COVERAGE AUDIT

## Trace Analysis

1. **Packet Capture:**
   - Packets are captured natively via Scapy either in `live_sniff_worker` / `replay_pcap_worker` for live/replay mode, or within `sniff(offline=...)` in the `/api/validation/run` endpoint for validation sessions.
   - Packets are passed to `analyzer.analyze_packet(pkt)`.

2. **Alert Generation:**
   - Inside `analyzer.py`, `ids_engine.run_checks()` evaluates the payload against Suricata rules and the dynamic IOC list.
   - Alerts are returned as an array of dictionaries attached to the parsed packet.

3. **MITRE Technique Mapping:**
   - Both Suricata rules and IOC matches contain hard-mapped `mitre_technique` and `mitre_tactic` fields (e.g., `T1552` -> `Credential Access`).
   - These fields successfully survive the serialization boundary and reach the React frontend.

4. **Validation Session:**
   - `main.py` endpoint `/api/validation/run` executes a stateless full-PCAP analysis.
   - It aggregates alerts by `category`, `src_ip`, and `dst_ip`, recalculating `threat_score`, `confidence`, and `evidence_packets`.
   - The session results are returned to the client and currently stored *only* in the local `useState` hook of `DetectionValidationLab.tsx`. The backend discards the session immediately after returning it.

5. **Reporting:**
   - `Reports.tsx` utilizes `store.ts` (which tracks live/replay state globally) to export CSV/PDF/JSON.
   - `DetectionValidationLab.tsx` provides isolated exports for specific validation sessions.

## Identified Architecture Gaps for Phase 5

1. **Lack of Backend Aggregation:**
   - The requirement "Create a backend coverage model" dictates that the backend must globally track statistics across *all* live sessions and validation runs.
   - Currently, `main.py` has no global coverage state object. It does not track historical rule triggers, false positive rates, or cumulative evidence packets.

2. **Stateless Validation Runs:**
   - `/api/validation/run` must be modified to persist its generated session metrics into the new backend coverage model before returning the response.

3. **Stateless Live Sniffing:**
   - `check_queue_and_send` or `run_checks` must be instrumented to update the backend coverage model incrementally when live alerts are generated.

4. **Missing Coverage Engine Endpoints:**
   - The frontend will require a new endpoint (e.g., `GET /api/coverage/stats`) to retrieve the aggregated Coverage Model, Rule Effectiveness, and False Positive stats.

5. **Validation History State:**
   - Validation History is requested as part of the Detection Engineering Page. Because the backend doesn't save historical runs (only returning the generated payload), we either need to cache recent runs in the backend, or sync the history to the frontend's `store.ts`.

## Next Steps (Pending Approval)
- Instantiate a global `CoverageEngine` class in the backend.
- Instrument `validation_run` and `check_queue_and_send` to feed data into `CoverageEngine`.
- Build the `DetectionEngineering.tsx` dashboard.
