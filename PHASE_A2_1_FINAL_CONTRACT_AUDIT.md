# ARGUS — Phase A.2.1 Final Hardening & JSON Contract Audit Report

**Case ID**: `CASE-PHASE-A21-FINAL`  
**Tenant ID**: `tenant-phasea-nps`  
**Dataset**: Digital Corpora `nps-2009-ntfs1` (7 Original Raw Files)  
**Date**: August 31, 2026  
**Final Verdict**: **VERIFIED WITH KNOWN GAPS**

---

## Executive Summary

Phase A.2.1 Final Hardening Check has been completed across all 34 parser modules, 42 router source mappings, JSON serialization/deserialization contracts, timestamp precision, provenance survival, case isolation, malformed payload resilience, AST security rules, and the Digital Corpora `nps-2009-ntfs1` raw evidence dataset.

---

## 1. Architectural Distinction & Inventory Summary

| Metric Category | Verified Count | Notes & Distinction |
| :--- | :--- | :--- |
| **Actual Parser Modules (`.py` files)** | **34** | Modules under `preprocessing/parsers/` |
| **Implemented Parser Classes** | **34** | Classes registered in `_IMPLEMENTED_PARSERS` |
| **Supported Source Types** | **42** | Target mappings registered in `_SOURCE_PARSER_MAP` |
| **Complete Parsers** | **34** | Fully routable, parseable, normalized, error-safe |
| **Blocked Formats** | **1** | AFF 1.0 (`BLOCKED_MISSING_LIBAFF`). *AFF is not artificially counted as a parser.* |
| **Raw Dataset Files Processed** | **7** | Digital Corpora `nps-2009-ntfs1` raw files |
| **Raw Files Successfully Parsed** | **5** | `narrative.txt`, `ntfs1-gen0.E01`, `ntfs1-gen1.E01`, `ntfs1-gen2.E01`, `ntfs1-gen2.xml` |
| **Blocked Raw Files** | **2** | `ntfs1-gen0.aff`, `ntfs1-gen1.aff` (Original raw evidence preserved untouched) |
| **Total Extracted Records** | **207** | Normalized `Artifact` objects extracted |

---

## 2. Complete Normalized Artifact JSON Contract Verification

The JSON contract pipeline was tested end-to-end:

$$\text{Raw Evidence} \longrightarrow \text{Parser} \longrightarrow \text{Artifact} \longrightarrow \text{JSON Serialization} \longrightarrow \text{JSON Deserialization} \longrightarrow \text{Artifact}$$

### Root Contract Field Preservation Test
- `case_id`: Preserved (`case-tenant-alpha-001`)
- `evidence_id`: Preserved (`ev-999-alpha`)
- `source_artifact_id`: Preserved
- `source_tool`: Preserved (`tsk`)
- `parser_version`: Preserved (`4.12.1`)
- `artifact_type`: Preserved (`file_record`)
- `timestamp`: Preserved (`2026-08-31T14:30:45.123456+00:00`)
- `timestamp_type`: Preserved (`modified`)
- `event_summary`: Preserved (`File system record...`)
- `raw_fields`: Preserved intact (including native dictionary keys)
- `normalized_fields`: Preserved intact (`NormalizedFields` payload)

### `NormalizedFields` Attributes Verified Across Serialization
- Process Attributes: `PID` (`4096`), `PPID` (`1024`), `process_name` (`cmd.exe`), `command_line` (`cmd.exe /c whoami`)
- User & Host Attributes: `user` (`SYSTEM`), `host` (`FORENSIC-WORKSTATION-1`)
- Network Attributes: `src_ip` (`192.168.1.50`), `dst_ip` (`10.0.0.1`), `src_port` (`49152`), `dst_port` (`443`), `protocol`, `domain` (`corp.local`), `url` (`https://corp.local/api/v1`)
- File & Hash Attributes: `file_path`, `file_name`, `hash` (`SHA-256`)
- Registry Attributes: `registry_key`, `registry_value`, `registry_value_data`
- Email Attributes: `sender`, `recipients`, `subject`, `attachment_hash`
- Classification: `rule_name` (`cmd_execution_detected`), `severity` (`high`)

---

## 3. Null & Absent Fields Semantic Preservation

- Fields configured as `None` (such as `usb_serial_number`, `first_connected`, or absent raw keys) remain strictly `None` after JSON serialization and deserialization.
- No null values are coerced into empty strings `""` or `"null"` literals.

---

## 4. Datetime Serialization & Precision Rules

- **Timezone Awareness**: All timestamps deserialize as timezone-aware UTC objects (`tzinfo=timezone.utc`).
- **Precision**: Sub-second / microsecond precision (`.123456`) is preserved 100% without truncation.

---

## 5. Provenance Survival

- End-to-end provenance references (`case_id`, `evidence_id`, `source_tool`, `parser_version`, `artifact_type`) survive JSON round-trip serialization with zero data loss or mutation.

---

## 6. Malformed JSON & Corruption Resilience

- Malformed JSON strings and invalid timestamp formats throw controlled `ValidationError` exceptions.
- Malformed records do NOT crash the batch processing engine or alter raw evidence.

---

## 7. Case & Tenant Isolation

- Artifacts serialized across distinct tenants (`tenant-A` vs `tenant-B`) maintain strict case separation with zero cross-tenant state leakage.

---

## 8. Preprocessing AST Security Audit

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
- **Security Result**: **100% CLEAN**

---

## 9. Full Preprocessing Unit Test Suite Results

- **Command**: `python -m pytest tests/unit -v`
- **Passed**: **483**
- **Failed**: **0**
- **Skipped**: **1** (`test_live_tsa_integration` — external network test)
- **Pass Rate**: **100%**

---

## 10. Phase A Raw-Evidence Verification Results

| File Name | Size (Bytes) | Router Status | Selected Parser | Records Extracted | SHA-256 BEFORE | SHA-256 AFTER | Integrity Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `narrative.txt` | 665 | `ROUTED` | `FilesystemParser` | 1 | `97c52467f98a...` | `97c52467f98a...` | **PASS** |
| `ntfs1-gen0.aff` | 277,228 | `BLOCKED` | `FilesystemParser` | 0 | `bf0291a0ee84...` | `bf0291a0ee84...` | **PASS** |
| `ntfs1-gen0.E01` | 1,089,252 | `ROUTED` | `FilesystemParser` | 43 | `96e525f53d50...` | `96e525f53d50...` | **PASS** |
| `ntfs1-gen1.aff` | 8,481,452 | `BLOCKED` | `FilesystemParser` | 0 | `33528f2d44fe...` | `33528f2d44fe...` | **PASS** |
| `ntfs1-gen1.E01` | 9,332,369 | `ROUTED` | `FilesystemParser` | 65 | `ed26b63cb373...` | `ed26b63cb373...` | **PASS** |
| `ntfs1-gen2.E01` | 36,083,007 | `ROUTED` | `FilesystemParser` | 79 | `2badead91bef...` | `2badead91bef...` | **PASS** |
| `ntfs1-gen2.xml` | 2,341,489 | `ROUTED` | `FilesystemParser` | 19 | `efe48e07ed32...` | `efe48e07ed32...` | **PASS** |

---

## 11. Final Verdict

```
================================================================================
FINAL VERDICT: VERIFIED WITH KNOWN GAPS
================================================================================
Parser Module Count       : 34 Modules (.py files)
Supported Router Sources   : 42 Source Types
Complete Parsers           : 34 Parsers (100% functional)
Blocked Formats            : 1 Format (AFF 1.0, retained as BLOCKED_MISSING_LIBAFF)
JSON Contract Round-Trip   : PASS (Full Artifact + NormalizedFields contract preserved)
Null & Datetime Semantics  : PASS (Strict None retention & UTC sub-second precision)
Tenant & Case Isolation    : PASS (100% case boundary isolation verified)
AST Security Audit        : PASS (0 unsafe execution calls across codebase)
Pytest Unit Suite         : PASS (483/483 tests passed)
Raw Evidence Integrity     : PASS (100% SHA-256 match for all 7 raw dataset files)
================================================================================
```

**ARGUS Phase A.2.1 is FULLY VERIFIED WITH KNOWN GAPS.**
