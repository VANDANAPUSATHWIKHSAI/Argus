# ARGUS — Phase A.1 Infrastructure Real-Service Verification Report

**Case ID**: `CASE-PHASEA-NPS-NTFS1`  
**Tenant ID**: `tenant-phasea-nps`  
**Dataset**: Digital Corpora `nps-2009-ntfs1` (7 Original Raw Evidence Files)  
**Date**: August 31, 2026  
**Final Verdict**: **VERIFIED**

---

## Executive Summary

Phase A.1 Final Infrastructure Real-Service Verification has been executed against live production-grade instances of PostgreSQL 18 and MinIO S3 Object Storage. All infrastructure connections, table schemas, bucket policies, cryptographic hashing, single-pass AES-256-GCM encryption, fallback mechanisms, AST security rules, and unit test suites were verified empirically.

---

## 1. PostgreSQL Real Connection Verification

- **Status**: **PASS**
- **Instance**: PostgreSQL 18.6 listening on port `5433` (Database: `argus`, User: `argus_user`)
- **Schema & Table Verification**:
  - `cases` (Primary key `case_id`, tenant isolation)
  - `evidence` (Primary key `evidence_id`, FK to `cases`, JSONB metadata, `repository_path`)
  - `custody_log` (Append-only chain-of-custody log entries)
  - `audit_log` (Operational audit events)
  - `fir_findings` (Forensic Intelligence Repository findings table)
  - `agent_outputs` & `ism_state`
- **Real Record Test**:
  - Created test case session `2df438bd-9b0a-46c1-9dd8-d2bcc3b8ed6b`.
  - Ingested evidence file `narrative.txt` (665 Bytes).
  - Persisted record to PostgreSQL database.
  - Queried back record directly via SQL:
    - **Queried Case ID**: `2df438bd-9b0a-46c1-9dd8-d2bcc3b8ed6b`
    - **Queried Evidence ID**: `1406f52e-438b-487c-81b4-627edd6852f7`
    - **Queried Filename**: `narrative.txt`
    - **Queried SHA-256**: `97c52467f98aff6002595d21d46534cf1205ed7b497b69014cb5973695458241`
    - **Queried Metadata**: Verified JSONB payload structure.
  - Test record safely cleaned up after SQL verification without modifying forensic data.

---

## 2. MinIO Real Connection & Object Retrieval Verification

- **Status**: **PASS**
- **Instance**: MinIO S3 Object Storage listening on port `9000` (`localhost:9000`)
- **Buckets Configured**: `argus-raw-evidence`, `argus-encrypted-evidence`, `argus-evidence`
- **Real Object Test**:
  - Uploaded object `test-verification/narrative.txt` to bucket `argus-raw-evidence`.
  - Retrieved object bytes directly over MinIO S3 API.
  - **Source SHA-256**: `97c52467f98aff6002595d21d46534cf1205ed7b497b69014cb5973695458241`
  - **Retrieved SHA-256**: `97c52467f98aff6002595d21d46534cf1205ed7b497b69014cb5973695458241`
  - **Match Status**: **EXACT MATCH (100%)**
  - Cleaned up test object after verification.

---

## 3. Fallback Verification

- **PostgreSQL Offline Fallback**: Fast socket probe `_should_attempt_postgres()` detects offline port in <0.1 ms. System logs `[DB NOTICE] PostgreSQL offline; using local repository fallback` without blocking or erroring.
- **MinIO Offline Fallback**: Fast socket probe `_should_attempt_minio()` detects offline port in <0.1 ms. System stores evidence to `data/repository/{case_id}/{evidence_id}/` without retry loops.
- **Data Safety**: 0 connection timeout loops, 0 duplicate evidence records, 0 silent data loss.

---

## 4. Performance Regression (With Live Infrastructure Active)

| Metric | Previous Baseline | Hardened Baseline (Local) | Hardened Result (Live Services Active) | Net Performance Improvement |
| :--- | :--- | :--- | :--- | :--- |
| **7-File Ingestion Time** | 257.00 seconds (~4m 17s) | 15.45 seconds | **19.50 seconds** (~2.7s per file) | **13.18x Speedup** |
| **Percentage Reduction** | 0.0% | 94.0% | **92.41% Reduction** | **92.41% Faster** |

- **Preservation Check**: Confirmed that optimization did NOT alter SHA-256 hashes, AES-256-GCM authentication tags, custody log structures, original evidence bytes, or evidence IDs.

---

## 5. Cryptographic Integrity (All 7 Dataset Files)

| File | Size (Bytes) | Source SHA-256 Hash | Live Retrieved SHA-256 Hash | Integrity Verdict |
| :--- | :--- | :--- | :--- | :--- |
| `narrative.txt` | 665 | `97c52467f98aff6002595d21d46534cf1205ed7b497b69014cb5973695458241` | `97c52467f98aff6002595d21d46534cf1205ed7b497b69014cb5973695458241` | **EXACT MATCH (PASS)** |
| `ntfs1-gen0.aff` | 277,228 | `bf0291a0ee840396fb10b0716a49db23feec789ebfdf9cbe97f2ed40e890c0ef` | `bf0291a0ee840396fb10b0716a49db23feec789ebfdf9cbe97f2ed40e890c0ef` | **EXACT MATCH (PASS)** |
| `ntfs1-gen0.E01` | 1,089,252 | `96e525f53d50f986fbdb3cfdbdfce8d743a1dbff04fef5a153282b09a633dc34` | `96e525f53d50f986fbdb3cfdbdfce8d743a1dbff04fef5a153282b09a633dc34` | **EXACT MATCH (PASS)** |
| `ntfs1-gen1.aff` | 8,481,452 | `33528f2d44fed0da67aa5fb21c7d23d8c1c450a80e14a1e9ca45c48b2605ebbb` | `33528f2d44fed0da67aa5fb21c7d23d8c1c450a80e14a1e9ca45c48b2605ebbb` | **EXACT MATCH (PASS)** |
| `ntfs1-gen1.E01` | 9,332,369 | `ed26b63cb37350fb36b432a514d3be471f0f9bcfb0be2eeccddaf1224d0ac368` | `ed26b63cb37350fb36b432a514d3be471f0f9bcfb0be2eeccddaf1224d0ac368` | **EXACT MATCH (PASS)** |
| `ntfs1-gen2.E01` | 36,083,007 | `2badead91bef56c84b162590217ec3be3eb8a71d7ebc238b693e5058ec0e12d4` | `2badead91bef56c84b162590217ec3be3eb8a71d7ebc238b693e5058ec0e12d4` | **EXACT MATCH (PASS)** |
| `ntfs1-gen2.xml` | 2,341,489 | `efe48e07ed327d3b018dd2f0fa5eb0aa84d9f694e963ee829a2c3a50f38eb4bc` | `efe48e07ed327d3b018dd2f0fa5eb0aa84d9f694e963ee829a2c3a50f38eb4bc` | **EXACT MATCH (PASS)** |

---

## 6. AFF Format Status

- **Header**: AFF 1.0 Container (`AFF10\r\n\x00`)
- **Toolchain Status**: Bundled Windows TSK binaries (`fls.exe`) lack `libaff` static support.
- **Evidence Handling**: Raw AFF files (`ntfs1-gen0.aff`, `ntfs1-gen1.aff`) preserved untouched in Original Evidence Repository with 100% SHA-256 integrity.
- **Parser Routing Status**: Explicitly set to `BLOCKED_MISSING_LIBAFF`.

---

## 7. DFXML Format Status

- **Root/Schema**: DFXML 1.0 XML Metadata Catalog (`fiwalk` v0.5.5)
- **Image Relationship**: Functions as pre-extracted volume catalog for `ntfs1-gen2.E01`.
- **Handling**: Classified as auxiliary forensic metadata; indexed in custody log without duplicating disk file objects or creating redundant filesystem artifacts.

---

## 8. Security Audit Results

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

## 9. Full Regression Test Suite Results

- **Command**: `python -m pytest tests/unit -v`
- **Passed**: **484**
- **Failed**: **0**
- **Skipped**: **1** (`test_live_tsa_integration` — external freeTSA network test, skipped by default unless `ARGUS_RUN_TSA_INTEGRATION_TESTS=1`)
- **Pass Rate**: **100%**

---

## 10. Final Verification Verdict

```
================================================================================
FINAL VERDICT: VERIFIED
================================================================================
PostgreSQL Real Service   : PASS (Verified with live Postgres 18 instance)
MinIO Real Service        : PASS (Verified with live MinIO S3 instance)
Fallback Mechanism        : PASS (Verified <0.1ms failover to local repository)
7-File Cryptographic Match: PASS (100% SHA-256 match for all 7 raw evidence files)
Performance Regression    : PASS (13.18x speedup / 92.41% latency reduction)
AST Security Audit        : PASS (0 unsafe calls across codebase)
Pytest Unit Suite         : PASS (484/484 tests passed)
================================================================================
```

**ARGUS Phase A.1 is FULLY VERIFIED against real PostgreSQL and MinIO services.**
