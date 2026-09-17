# PCAP REAL EVIDENCE EXECUTION AUDIT REPORT

**Date**: 2026-09-17 15:27:14 UTC  
**Target Evidence**: `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\PCAP\2026-09-11-traffic-analysis-exercise.pcap`  
**PCAP File Size**: 56.73 MB (59,484,402 bytes)  
**Total Raw PCAP Artifacts Extracted**: 2,053  
**Total FCRs Correlated**: 498  
**Total PCAP FIR Findings**: 3  
**Total E2E Execution Runtime**: 112.60 seconds  
**Active Pipeline Components**: 19/21  

---

## 1. Pipeline Execution Metrics & Performance

| Pipeline Stage | Runtime | Component / Engine | Outputs & Artifacts Produced |
| :--- | :---: | :--- | :--- |
| **Stage 1: PcapParser** | **59.40s** | Zeek 8.2.2 + Suricata 7.0.3 | 2,053 raw network artifacts (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `weird.log`, `eve.json`). |
| **Stage 2: Normalization** | **0.45s** | Normalizer (Schema v2.0) | 2,053 normalized network artifacts with UTC timestamps. |
| **Stage 3: Entity Extractor** | **1.20s** | ArtifactExtractor | 559 atomic IP, domain, URL, and Hash entities. |
| **Stage 4: FCR Correlation** | **2.10s** | FCREngine | 498 correlated network FCR records. |
| **Stage 5: Evidence Consolidation** | **1.15s** | EvidenceConsolidationEngine | 1,130 Unified Artifact Indicators (UAIs). |
| **Stage 6: Network Engine** | **1.85s** | NetworkAnalysisEngine | 3 network findings across 4 sub-analyzers. |
| **Stage 7: Sanitization Gateway** | **1.40s** | SanitizationGateway & FIRRepo | 3 sanitized FIR findings persisted in PostgreSQL database. |

---

## 2. Artifact Breakdown by Source Tool & Protocol

| Source Tool | Artifact Type | Protocol / Event | Count | Description |
| :--- | :--- | :--- | :---: | :--- |
| `zeek` | `network_connection` | Network Connection | 368 | Network telemetry record extracted from PCAP | 
| `zeek` | `dns_query` | Dns Query | 141 | Network telemetry record extracted from PCAP | 
| `zeek` | `http_request` | Http Request | 102 | Network telemetry record extracted from PCAP | 
| `zeek` | `ssl_handshake` | Ssl Handshake | 97 | Network telemetry record extracted from PCAP | 
| `zeek` | `file_transfer` | File Transfer | 69 | Network telemetry record extracted from PCAP | 
| `zeek` | `network_anomaly` | Network Anomaly | 6 | Network telemetry record extracted from PCAP | 
| `suricata` | `dns_query` | Dns Query | 256 | Network telemetry record extracted from PCAP | 
| `suricata` | `ids_alert` | Ids Alert | 4 | Network telemetry record extracted from PCAP | 
| `suricata` | `network_event` | Network Event | 415 | Network telemetry record extracted from PCAP | 
| `suricata` | `ssl_handshake` | Ssl Handshake | 90 | Network telemetry record extracted from PCAP | 
| `suricata` | `http_request` | Http Request | 102 | Network telemetry record extracted from PCAP | 
| `suricata` | `file_transfer` | File Transfer | 62 | Network telemetry record extracted from PCAP | 
| `suricata` | `network_flow` | Network Flow | 341 | Network telemetry record extracted from PCAP | 

---

## 3. Pipeline Health & Active Components

- **Active Tools**: Zeek (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `weird.log`), Suricata (`eve.json` alerts & flows).
- **Sub-Analyzers Active**: DNSAnalyzer, HTTPAnalyzer, TLSAnalyzer, SessionReconstructor.
- **Infrastructure Engines**: FCREngine, EvidenceConsolidationEngine, SanitizationGateway, FIRRepository.
- **Execution Errors**: 0 unhandled exceptions.
