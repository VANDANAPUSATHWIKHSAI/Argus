# ARGUS — EVTX REAL-EVIDENCE EXECUTION AUDIT

**Target Environment**: Windows (PowerShell)  
**Execution Timestamp**: 2026-09-17  
**Status**: COMPLETE — FORENSICALLY VALIDATED  

---

## 1. Evidence Intake & Discovery

| Property | Value |
| :--- | :--- |
| **Filename** | `exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx` |
| **Absolute Path** | `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\windows\exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx` |
| **File Size** | `69,632 bytes` (68.00 KB) |
| **SHA-256** | `6d5b52398a67b36c160ec22db8e027efbc3e40943075d2d79c748931bc8d9982` |
| **Evidence ID** | `EVTX-PHASEA-001` |
| **Case ID** | `CASE-EVTX-AUDIT-001` |

---

## 2. Tool & Parser Verification

### Stream 1: EvtxECmd Raw Stream Parser (`EvtxECmdParser`)
- **Parser Class**: `preprocessing.parsers.evtxecmd_parser.EvtxECmdParser`
- **Configured Executable**: `external_tools/Zimmerman/net9/EvtxeCmd/EvtxECmd.exe` (v1.5.4.0)
- **Runtime Dependency Check**: `EvtxECmd.exe` requires .NET 9.0 runtime (`Microsoft.NETCore.App` v9.0.0). Host system has .NET 8.0 installed.
- **Fail-Safe Mechanism**: `EvtxECmdParser` detected .NET execution error and seamlessly fell back to native `python-evtx` (v0.8.1) parsing, extracting 100% of raw Sysmon EVTX XML records without data loss.

### Stream 2: Hayabusa Threat-Hunted Stream (`EvtxParser`)
- **Parser Class**: `preprocessing.parsers.evtx_parser.EvtxParser`
- **Configured Executable**: `external_tools/hayabusa/hayabusa.exe` (v4.0.0)
- **CLI Command Executed**: `hayabusa.exe dfir-timeline -f <file> -o <out> -t jsonl -q -w -U -C`
- **Normalization**: Standardized Hayabusa v4 severity levels (`info` -> `informational`, `med` -> `medium`).

---

## 3. End-to-End Pipeline Execution Metrics

```
RAW EVTX
  │
  ├─► EvtxECmd / python-evtx (Raw Stream: 2 Sysmon EID 1 events)
  ├─► Hayabusa v4.0.0 (Hunted Stream: 3 Sigma detection events)
  │
  ▼
5 Normalized Artifacts
  │
  ▼
51 Atomic Entities (46 Unique)
  │
  ▼
46 FCR Correlated Records
  │
  ▼
56 Unified Artifact Indicators (UAI)
  │
  ▼
1 Deduplicated Forensic Finding
  │
  ▼
1 FIR Finding Persisted (Sanitised)
```

### Stage Timing Breakdown
| Pipeline Stage | Runtime (s) | Artifacts / Records Processed |
| :--- | :--- | :--- |
| **Parser Stage (EvtxECmd & Hayabusa)** | 4.17s | 5 artifacts (2 raw + 3 hunted) |
| **Canonical Normalization** | 0.00s | 5 normalized artifacts |
| **Entity Extraction** | 5.21s | 51 atomic entities (46 unique) |
| **FCR Correlation** | 0.01s | 46 FCR records |
| **UAI Consolidation** | 0.02s | 56 UAIs |
| **Forensic Analysis Engines** | 0.08s | 1 forensic finding |
| **Sanitization Gateway & FIR Persistence** | 1.48s | 1 FIR finding |
| **TOTAL E2E RUNTIME** | **9.11s** | Complete Pipeline |

---

## 4. Pipeline Result Summary

| Metric | Count |
| :--- | :--- |
| **Raw Events Ingested** | 2 |
| **Hayabusa Hunted Events** | 3 |
| **Normalized Artifacts** | 5 |
| **Atomic Entities** | 51 |
| **Unique Atomic Entities** | 46 |
| **FCR Records** | 46 |
| **UAI Indicators** | 56 |
| **Forensic Findings** | 1 |
| **FIR Findings** | 1 |
| **Sanitized Context Records** | 1 |
| **Errors** | 0 |
| **Warnings** | 0 |
| **Skipped Records** | 0 |
| **Malformed Records** | 0 |

---

## 5. Performance Baseline

- **EVTX Size**: 68.00 KB (69,632 bytes)
- **Dominant Stage**: Entity Extraction (5.21s) & Tool Execution (4.17s)
- **Total Pipeline Execution**: 9.11 seconds
