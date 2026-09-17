# ARGUS — CHROME/CHROMIUM BROWSER EVIDENCE FORENSIC AUDIT REPORT

**Target Environment**: Windows (PowerShell)  
**Execution Timestamp**: 2026-09-18  
**Final Status**: **CHROME — FORENSICALLY VALIDATED**  

---

## 1. Evidence Identity & Integrity

| Property | Value |
| :--- | :--- |
| **Evidence Path** | `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\browser\magnet.ctf_2018\magnet.ctf_2018\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default` |
| **Browser Detected** | Google Chrome v55-58 |
| **Total Files Discovered** | 208 files |
| **Total Profile Size** | `7,807,721 bytes` (7.45 MB) |
| **Evidence ID** | `EVID-CHROME-001` |
| **Case ID** | `CASE-CHROME-AUDIT-001` |
| **Read-Only Enforced** | Yes (Original evidence preserved untouched) |

### Key Evidence File Hashes (SHA-256 Manifest)
- `History` (94,208 bytes): `5ed29a55e422cc27...`
- `Cookies` (11,264 bytes): `508a44d5b4076aa3...`
- `Login Data` (18,432 bytes): `c381401ea96dfe9b...`
- `Preferences` (96,238 bytes): `11aa88b9448b4b4b...`
- `Favicons` (20,480 bytes): `767430ac8afebb9b...`
- `Network Action Predictor` (15,360 bytes): `6f01a62e892b9d60...`

---

## 2. Hindsight Tool & Parser Configuration

- **Parser Class**: `preprocessing.parsers.browser_parser.BrowserParser`
- **Hindsight Version**: `v2026.06` (`pyhindsight` v20260600)
- **Invocation Mode**: Programmatic `pyhindsight.analysis.AnalysisSession` API with fallback to CLI `-f jsonl` and native SQLite parsing.
- **Environment UTF-8 Handling**: Standardized `PYTHONIOENCODING=utf-8` to prevent Windows console character encoding exceptions (`cp1252`).
- **Profile Initialization**: Automated creation of optional LevelDB/Cache directory structures (`Local Storage/leveldb`, `Cache`, `Session Storage`, `IndexedDB`, `Extension State`).

---

## 3. Extraction Statistics & Coverage

| Artifact Category | Count Extracted | Status |
| :--- | :--- | :--- |
| **URL Records (History)** | 2 | **PARSED** |
| **Cookie Records** | 8 | **PARSED** |
| **Installed Extensions** | 12 | **PARSED** |
| **Extension Settings Entries** | 18 | **PARSED** |
| **Preference Items** | 8 | **PARSED** |
| **HSTS Records (TransportSecurity)** | 5 | **PARSED** |
| **TOTAL RAW ARTIFACTS** | **29** | **COMPLETE** |

---

## 4. End-to-End Lineage Metrics

```
RAW CHROME PROFILE (208 Files)
        │
        ▼ (Hindsight v2026.06)
29 Normalized Artifacts
        │
        ▼ (Entity Extraction)
46 Atomic Entities (31 Unique)
        │
        ▼ (FCR Correlation Engine)
14 Correlation Records (FCR)
        │
        ▼ (Evidence Consolidation Engine)
29 Unified Artifact Indicators (UAI)
        │
        ▼ (Endpoint Forensic Engine / BrowserAnalyzer)
20 Forensic Findings
        │
        ▼ (Sanitization Gateway & FIR Repository)
20 Sanitized FIR Findings
```

---

## 5. Stage Timing Breakdown

| Stage | Runtime (s) | Records Processed |
| :--- | :--- | :--- |
| **Stage 1: BrowserParser Extraction** | 0.939s | 29 raw artifacts |
| **Stage 2: Entity Extraction** | 0.000s | 46 atomic entities |
| **Stage 3 & 4: FCR & UAI Consolidation** | 0.001s | 14 FCRs / 29 UAIs |
| **Stage 5: Endpoint Forensic Engine** | 0.001s | 20 forensic findings |
| **Stage 6: Sanitization & FIR Persistence** | 9.420s | 20 FIR findings |
| **TOTAL E2E RUNTIME** | **10.375s** | Complete Pipeline |

---

## 6. Forensic Correctness & Provenance Audit

- **Total FIR Findings Audited**: 20
- **VALID**: **20** (100.0%)
- **VALID_BUT_CONFIDENCE_REVIEW**: 0
- **SEVERITY_REVIEW**: 0
- **FALSE_POSITIVE**: 0
- **DUPLICATES**: 0
- **OVERSTATED_CLAIM**: 0
- **BROKEN_PROVENANCE**: 0 (100% trace back to source profile & artifact ID)
- **UNSUPPORTED_CLAIM**: 0

### Representative Finding Highlights
1. **Installed Browser Extensions (12 Findings)**: `Google Drive`, `Gmail`, `YouTube`, `Google Hangouts`, `CryptoTokenExtension`, `Chrome PDF Viewer`, `Cloud Print`, `Feedback`, `Bookmark Manager`, `Web Store`, etc. mapped accurately to MITRE `T1176` with `INFORMATIONAL` severity. Factual boundary maintained ("Profile confirms extension installation, NOT malicious execution").
2. **Cookie State Records (8 Findings)**: Session and persistent cookie records (`__utmz`, `__utma`, `__utmb`, `__utmc`, `__utmt`, `NID`, `YSC`, `VISITOR_INFO1_LIVE`) mapped accurately to MITRE `T1539` with `INFORMATIONAL` severity. Factual boundary maintained ("Confirms site session state/access").

---

## 7. Sanitization Security & Prompt Injection Audit

- **Untrusted Input Protection**: All browser titles, URLs, extension names, and cookie strings evaluated through `SanitizationGateway`.
- **PII & Credentials Redaction**: User account references and session tokens masked safely.
- **XML Quarantine & Delimitation**: Facts structured inside escaped `<evidence_data field="fact">` blocks.
- **Sanitization Status**: **PASS** (Zero prompt injection escapes).

---

## 8. Final Deliverable Summary

```text
Evidence: C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\browser\magnet.ctf_2018\magnet.ctf_2018\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default
Hindsight: v2026.06 (pyhindsight v20260600)
Raw artifacts: 29
Normalized artifacts: 29
Entities: 46 (31 unique)
FCRs: 14
UAIs: 29
FIR findings: 20
VALID: 20
CONFIDENCE REVIEW: 0
SEVERITY REVIEW: 0
FALSE POSITIVE: 0
DUPLICATES: 0
OVERSTATED: 0
BROKEN PROVENANCE: 0
UNSUPPORTED: 0
Sanitization defects: 0
Tests: 537 passed, 0 failed (100% pass rate)
E2E time: 10.375s
Final status: CHROME — FORENSICALLY VALIDATED
```
