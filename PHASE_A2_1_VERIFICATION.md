# ARGUS — Phase A.2.1 Real Raw-Evidence Verification Report

**Case ID**: `CASE-PHASE-A21`  
**Tenant ID**: `tenant-phasea-nps`  
**Dataset**: Digital Corpora `nps-2009-ntfs1` (7 Original Raw Files)  
**Date**: August 31, 2026  
**Final Verdict**: **VERIFIED WITH KNOWN GAPS**

---

## Executive Summary

Phase A.2.1 Parser, JSON Normalization, and AFF Support Audit has been executed against all 7 original raw evidence files in the Digital Corpora `nps-2009-ntfs1` dataset. Every file was processed through SHA-256 pre-calculation, `ParserRouter` evaluation, parser execution, schema normalization, SHA-256 post-calculation, and integrity comparison.

---

## 1. Raw-Evidence Verification Matrix (All 7 Dataset Files)

| File Name | Size (Bytes) | Format Description | Router Result | Selected Parser | Records Extracted | Normalization | Provenance | SHA-256 BEFORE | SHA-256 AFTER | Integrity | Status | Notes / Gap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `narrative.txt` | 665 | Case Narrative Text File | `ROUTED` | `FilesystemParser` | 1 | `text_record` | Full | `97c52467f98a...` | `97c52467f98a...` | **PASS** | `SUCCESS` | Case investigation note parsed |
| `ntfs1-gen0.aff` | 277,228 | AFF 1.0 Disk Image Container | `BLOCKED` | `FilesystemParser` | 0 | None | Full | `bf0291a0ee84...` | `bf0291a0ee84...` | **PASS** | `BLOCKED` | `BLOCKED_MISSING_LIBAFF` |
| `ntfs1-gen0.E01` | 1,089,252 | EnCase E01 Expert Witness Image | `ROUTED` | `FilesystemParser` | 43 | `file_record` | Full | `96e525f53d50...` | `96e525f53d50...` | **PASS** | `SUCCESS` | 43 filesystem records extracted |
| `ntfs1-gen1.aff` | 8,481,452 | AFF 1.0 Disk Image Container | `BLOCKED` | `FilesystemParser` | 0 | None | Full | `33528f2d44fe...` | `33528f2d44fe...` | **PASS** | `BLOCKED` | `BLOCKED_MISSING_LIBAFF` |
| `ntfs1-gen1.E01` | 9,332,369 | EnCase E01 Expert Witness Image | `ROUTED` | `FilesystemParser` | 65 | `file_record` | Full | `ed26b63cb373...` | `ed26b63cb373...` | **PASS** | `SUCCESS` | 65 filesystem records extracted |
| `ntfs1-gen2.E01` | 36,083,007 | EnCase E01 Expert Witness Image | `ROUTED` | `FilesystemParser` | 79 | `file_record` | Full | `2badead91bef...` | `2badead91bef...` | **PASS** | `SUCCESS` | 79 filesystem records extracted |
| `ntfs1-gen2.xml` | 2,341,489 | DFXML 1.0 Metadata Catalog | `ROUTED` | `FilesystemParser` | 19 | `file_record` | Full | `efe48e07ed32...` | `efe48e07ed32...` | **PASS** | `SUCCESS` | 19 catalog records extracted |

---

## 2. Performance Measurement Breakdown

| Processing Phase | Measured Runtime | Notes |
| :--- | :--- | :--- |
| **Router Determination Time** | 0.42 ms total | Layered signature & extension evaluation |
| **Parser Execution Time** | 937.31 ms total | Fast Sleuth Kit bodyfile parsing & XML extraction |
| **Schema Normalization Time** | Included in parser time | Conversion to `Artifact` + `NormalizedFields` |
| **Total Phase A.2.1 Processing Time** | **937.73 ms** (0.938 s) | All 7 files processed in under 1 second |

- **Fastest File**: `narrative.txt` (1.11 ms)
- **Slowest File**: `ntfs1-gen1.E01` (342.20 ms)
- **Total Records Extracted**: **207 Normalized Artifact Records**

---

## 3. Security Audit Verification

```
=== AST SECURITY AUDIT RESULTS ===
eval() calls                        : 0
exec() calls                        : 0
shell=True                          : 0
os.system()                         : 0
pickle.loads()                      : 0
evidence-originated command exec    : 0
arbitrary subprocess execution      : 0
```
- **Security Compliance**: **100% CLEAN**

---

## 4. Pytest Unit Suite Results

- **Command**: `python -m pytest tests/unit -v`
- **Passed**: **483**
- **Failed**: **0**
- **Skipped**: **1** (`test_live_tsa_integration` — external freeTSA network test, skipped by default unless `ARGUS_RUN_TSA_INTEGRATION_TESTS=1`)
- **Pass Rate**: **100%**

---

## 5. Parser Count & Status Summary

- **Total Implemented Parsers**: **35**
- **Total Supported Source Formats**: **42**
- **`COMPLETE` Count**: **34 Parsers**
- **`BLOCKED_MISSING_LIBAFF` Count**: **1 Format** (`.aff` container files)
- **`PARTIAL` Count**: **0**
- **`UNSUPPORTED` Count**: **0**

---

## 6. Final Phase A.2.1 Verdict

```
================================================================================
FINAL VERDICT: VERIFIED WITH KNOWN GAPS
================================================================================
Raw-Evidence Parsing      : PASS (All 5 routable files parsed without error)
Cryptographic Integrity    : PASS (100% SHA-256 match for all 7 raw evidence files)
JSON Schema Normalization : PASS (All records produce Artifact + NormalizedFields)
Provenance Chain          : PASS (Full case_id -> evidence_id -> source_tool chain)
AST Security Audit        : PASS (0 unsafe calls across codebase)
Pytest Unit Suite         : PASS (483/483 tests passed)
Known Format Gap          : AFF 1.0 containers (.aff) are preserved untouched with
                            100% SHA-256 integrity, with parser status explicitly
                            retained as BLOCKED_MISSING_LIBAFF due to missing static
                            libaff library in Windows Sleuth Kit binaries.
================================================================================
```

**ARGUS Phase A.2.1 is VERIFIED WITH KNOWN GAPS.**
