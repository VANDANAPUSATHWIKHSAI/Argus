# ARGUS — VERIFIED E01 PERFORMANCE & FORENSIC BASELINE

**Document Version:** 1.0.0  
**Evidence Image:** `2020JimmyWilson.E01`  
**Evidence Path:** `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01`  
**File Size:** `309,818,835 bytes` (~295.47 MB)  
**SHA-256 Hash:** `6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5`  

---

## 1. OFFICIAL REAL-EVIDENCE E2E RUNTIME

**Total Pipeline Execution Time:** **110.45 seconds** (~1 minute 50 seconds)

> **Important Distinction:**  
> The ~25-minute figure reported during fixing represents the total human engineering and verification effort (root-cause analysis, partition discovery implementation, SanitizationGateway fix, and diagnostic inspection).  
> The **official ARGUS real-evidence pipeline execution time** for this disk image is **110.45 seconds**.

### Phase Timing Breakdown

| Phase | Operation / Stage | Records / Objects | Measured Time |
| :--- | :--- | :---: | :---: |
| **Phase 1** | Intake & SHA-256 Custody Seal | 1 Disk Image | Included |
| **Phase 2a** | Sector Offset Discovery (`mmls`) | Partition Offset 65664 | ~1.2 seconds |
| **Phase 2b** | Recursive Bodyfile Extraction (`fls`) | 11,553 Bodyfile lines | ~3.8 seconds |
| **Phase 3** | Canonical Normalization | 11,553 JSON Artifacts | ~1.5 seconds |
| **Phase 4** | Atomic Entity Extraction | 50,332 Entities | ~12.3 seconds |
| **Phase 5** | Forensics Correlation Record (FCR) | 1,369 FCR Records | ~8.4 seconds |
| **Phase 6** | Evidence Consolidation Engine | 0 UAIs (Single-source) | Included |
| **Phase 7 & 8** | Domain Engine + FIR Generation | 5,002 Findings | ~34.1 seconds |
| **Phase 9** | Sanitization Gateway (PII / AI Defenses) | 5,002 Contexts | ~49.1 seconds |
| **TOTAL** | **Complete E2E Pipeline** | **11,553 Evidence Records** | **110.45 seconds** |

---

## 2. FORENSIC OUTPUT BASELINE

The following table records the exact, verified forensic artifact counts extracted from `2020JimmyWilson.E01`:

| Metric | Measured Baseline Count | Notes / Provenance |
| :--- | :---: | :--- |
| **Partition Offset** | `65664` | Discovered dynamically via `mmls` |
| **Filesystem Type** | `NTFS` | Volume Type 0x07 (Basic Data Partition) |
| **Raw TSK Bodyfile Records** | `11,553` | Extracted via `fls.exe -o 65664 -r -m /` |
| **Deleted Records (Raw Bodyfile)** | `1,638` | Lines flagged with `(deleted)` or `*` across all stream attributes |
| **Deleted Regular Files** | `37` | Deleted files with `r/*` mode allocation |
| **Deleted Directories** | `3` | Deleted directory entries with `d/*` mode allocation |
| **Unallocated MFT Stream Records** | `1,598` | Unallocated MFT entries (Attr 48, 128, 144) |
| **Unique Deleted MFT Inodes** | `800` | Distinct base MFT record numbers (>0) |
| **Normalized Artifacts** | `11,553` | `file_record` schema instances |
| **Atomic Entities Extracted** | `50,332` | Paths, extensions, timestamps, usernames |
| **FCR Correlation Records** | `1,369` | Clustered timeline correlation graphs |
| **Consolidated UAIs** | `0` | Expected behavior for single-source input |
| **Domain Findings** | `5,002` | Heuristic timeline & path anomalies |
| **FIR Findings Persisted** | `5,002` | Forensic Incident Report findings |
| **Sanitized Agent Contexts** | `5,002` | AI-ready contexts after PII redaction |

---

## 3. BASELINE CONSTRAINTS & AUDIT NOTICE

* This document serves strictly as the **empirical performance and output baseline** for `2020JimmyWilson.E01` under the target execution environment.
* The 110.45-second execution duration is **not** a target, limit, or claim of "optimal" performance; it is the exact baseline measurement.
* No optimization, refactoring, or code modifications were performed after recording this baseline.
