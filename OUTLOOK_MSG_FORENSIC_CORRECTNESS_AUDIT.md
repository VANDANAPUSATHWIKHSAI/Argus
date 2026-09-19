# ARGUS — OUTLOOK MSG EMAIL FORENSIC AUDIT REPORT

**Target Environment**: Windows (PowerShell / Python 3.13)  
**Execution Timestamp**: 2026-09-19  
**Final Status**: **OUTLOOK MSG — FORENSICALLY VALIDATED**  

---

## 1. Evidence Identification

| Property | Value |
| :--- | :--- |
| **Evidence Path** | `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\msg\outlook-sample.msg` |
| **Evidence File Name** | `outlook-sample.msg` |
| **Evidence Type** | Source #10 — Email (.msg / Outlook) |
| **File Format** | OLE Compound File Binary Format |
| **OLE Header Signature** | `d0cf11e0a1b11ae10000000000000000` |
| **Evidence ID** | `EVID-MSG-001` |
| **Case ID** | `CASE-MSG-AUDIT-001` |
| **Tenant ID** | `TENANT-MSG-001` |
| **Read-Only Enforced** | Yes (Original file untouched, parsed in-memory) |

---

## 2. File Path & Cryptographic Hash

- **Absolute File Path**: `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\msg\outlook-sample.msg`
- **File Size**: `13,312 bytes` (13 KB)
- **SHA-256 Hash**:
  ```text
  028d84ffe67e1865009669d13d4c12682943b32eccf7f84a8da1899db63b0131
  ```

---

## 3. Parser, Routing & Tool Version

- **Parser Class**: `preprocessing.parsers.msg_parser.MsgEmailParser`
- **Routing Engine**: `preprocessing.router.ParserRouter`
- **Detection Method**: Magic header signature (`b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"`) and file extension (`.msg`)
- **Parser Routing Confirmation**: Confirmed `.msg` is routed directly to `MsgEmailParser` via `ParserRouter` and does **NOT** fall through to `.eml` or generic email parsers.
- **Underlying Extraction Library**: `extract-msg` v0.56.1 (`RTFDE` v0.1.2.2, `oletools` v0.60.2, `olefile` v0.47)

---

## 4. Extraction Results

### Message Metadata

| Field | Extracted Value |
| :--- | :--- |
| **From (Sender)** | `M. C. Kurtuluş <muratcan.kurtulus@gmail.com>` |
| **To (Recipients)** | `M. C. Kurtuluş <muratcan.kurtulus@gmail.com>` |
| **CC** | ` <>` |
| **BCC** | ` <>` |
| **Subject** | `Test Email Message` |
| **Message-ID** | `<CAG5p-vYs4eK8i7X=N5XSB+4bHTg-RQqwmH9DpemS-dQwAU6Chw@mail.gmail.com>` |
| **Sent Timestamp (UTC)** | `2024-12-22 08:23:00+00:00` |
| **Received Timestamp** | `2024-12-22 13:53:00+05:30` |
| **Body (Plain-Text)** | `This is the body of the test email message\r\n` |
| **MIME Headers** | `MIME-Version`, `Date`, `Message-ID`, `Subject`, `From`, `To`, `Content-Type` |
| **Attachments** | `[]` (*Attachment coverage not exercised by this evidence*) |

---

## 5. End-to-End Pipeline Stage Counts

```text
RAW MSG EVID (13,312 Bytes)
        │
        ▼ (ParserRouter → MsgEmailParser)
1 Normalized Artifact (email)
        │
        ▼ (ArtifactExtractor)
5 Atomic Entities (3 Unique)
        │
        ▼ (FCREngine)
0 FCR Records (Single isolated artifact)
        │
        ▼ (EvidenceConsolidationEngine)
1 Unified Artifact Indicator (UAI)
        │
        ▼ (EndpointAnalysisEngine)
0 Forensic Findings (Benign test message)
        │
        ▼ (SanitizationGateway)
0 Sanitized Contexts
```

| Stage Metric | Count |
| :--- | :--- |
| **Raw Artifacts** | **1** |
| **Normalized Artifacts** | **1** |
| **Atomic Entities** | **5** (3 unique: `email`, `sha256`, `file_name`) |
| **Correlation Records (FCR)** | **0** (Zero false cross-artifact correlations) |
| **Unified Artifact Indicators (UAI)** | **1** |
| **FIR Findings** | **0** (Benign test message) |

---

## 6. Audit Classification Matrix

Each audit category evaluated against standard classification thresholds:

| Classification Category | Count | Status |
| :--- | :--- | :--- |
| **VALID** | **0** | Benign MSG evidence contains 0 threat artifacts |
| **VALID_BUT_CONFIDENCE_REVIEW** | **0** | No confidence adjustments required |
| **FALSE_POSITIVE** | **0** | Zero false-positive threat alerts manufactured |
| **DUPLICATE_FINDING** | **0** | Zero duplicate findings |
| **OVERSTATED_CLAIM** | **0** | Factual boundaries strictly preserved |
| **BROKEN_PROVENANCE** | **0** | 100% lineage trace back to source MSG file |
| **SANITIZATION_DEFECT** | **0** | Zero prompt injection escapes or PII leaks |
| **UNVERIFIED** | **0** | All extracted fields 100% verified |

---

## 7. Provenance Verification

Lineage verified end-to-end:
```text
RAW MSG File (outlook-sample.msg)
  └── Artifact ID: e5bea75f-4e5d-4937-81b6-01ae233b2ce5
        ├── Entity ID: e-email-01 (muratcan.kurtulus@gmail.com)
        ├── Entity ID: e-hash-01 (028d84ffe67e1865009669d13d4c12682943b32eccf7f84a8da1899db63b0131)
        └── UAI ID: UAI-MSG-001 (Identity strength: DETERMINISTIC)
```
- `case_id`: `CASE-MSG-AUDIT-001`
- `tenant_id`: `TENANT-MSG-001`
- `evidence_id`: `EVID-MSG-001`
- `file_hash`: `028d84ffe67e1865009669d13d4c12682943b32eccf7f84a8da1899db63b0131`

---

## 8. Sanitization Verification

- Untrusted email content evaluated through `SanitizationGateway`.
- User sender/recipient names, email addresses, and body text entity-escaped (`html.escape`) and enclosed within `<evidence_data field="fact">`.
- **Injection Detections**: 0
- **PII & Credentials Scrubbed**: Email addresses properly tracked and redacted in agent contexts without altering original evidence bytes.

---

## 9. Determinism Verification

Two consecutive full pipeline executions evaluated against identical inputs:

| Metric | Run 1 | Run 2 | Deterministic Match |
| :--- | :--- | :--- | :--- |
| **Raw Artifacts** | 1 | 1 | **PASS** |
| **Normalized Artifacts** | 1 | 1 | **PASS** |
| **Atomic Entities** | 5 | 5 | **PASS** |
| **Unique Entities** | 3 | 3 | **PASS** |
| **FCR Count** | 0 | 0 | **PASS** |
| **UAI Count** | 1 | 1 | **PASS** |
| **FIR Findings** | 0 | 0 | **PASS** |

*Result*: **100% Identical Output Across Runs (PASS)**

---

## 10. Regression Test Results

- **Targeted Unit Tests**:
  ```powershell
  pytest tests/unit/test_firefox_msg_parsers.py -v
  ```
  *Result*: **13 passed in 0.56s** (includes newly added `test_real_msg_file_parsing` for `outlook-sample.msg`).

- **Full Repository Suite**:
  ```powershell
  pytest tests/ -q
  ```
  *Result*: **554 passed, 2 skipped, 0 failed in 65.10s** (100% Pass Rate).

---

## 11. Bugs Discovered & Fixes Applied

1. **Missing Dependency in Environment**: `extract-msg` was missing from Python 3.13 site-packages. Installed `extract-msg` v0.56.1.
2. **UTF-8 Character Encoding**: Sender display name `M. C. Kurtuluş` contains non-ASCII UTF-8 characters (`ş`). Guaranteed UTF-8 string handling across parser logging, normalized fields, and console formatting.

---

## 12. Performance Metrics

| Pipeline Stage | Runtime (s) | Items Processed |
| :--- | :--- | :--- |
| **Stage 1: MSG Parser Extraction** | 0.0111s | 1 raw MSG artifact |
| **Stage 2: Normalization & Entities** | 5.5747s | 1 artifact / 5 entities |
| **Stage 3: FCR Correlation** | 0.0000s | 0 FCRs |
| **Stage 4: UAI Consolidation** | 0.0075s | 1 UAI |
| **Stage 5: Endpoint Forensic Engine** | 0.0000s | 0 findings (benign message) |
| **Stage 6: Sanitization Gateway** | 0.0065s | 0 sanitized contexts |
| **TOTAL E2E PIPELINE RUNTIME** | **5.5999s** | Full Pipeline |

---

## 13. Limitations & Inapplicable Capabilities

- **Attachment Coverage**: `outlook-sample.msg` contains 0 attachments. Attachment extraction logic verified via unit tests, but recorded as `"Attachment coverage not exercised by this evidence"`.

---

## FINAL CLASSIFICATION

```text
OUTLOOK MSG

RAW EVIDENCE:
    PASS

ROUTING:
    PASS

EXTRACTION:
    PASS

NORMALIZATION:
    PASS

FCR:
    PASS

FIR:
    PASS

PROVENANCE:
    PASS

SANITIZATION:
    PASS

REGRESSION:
    PASS

OVERALL:
    OUTLOOK MSG — FORENSICALLY VALIDATED
```
