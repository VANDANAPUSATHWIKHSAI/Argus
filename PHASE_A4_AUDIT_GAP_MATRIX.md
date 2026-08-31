# ARGUS — Phase A.4 Revised Architectural Audit Gap Matrix

**Date**: August 31, 2026  
**Audited Layer**: Stage 4 Forensic Finding Layer (`forensic_analysis/`, `fir/`, `sanitization/`)  
**Status**: **REVISED AUDIT COMPLETE** (No code modified, awaiting plan review)

---

## 1. Executive Summary

A deep architectural re-audit of the **ARGUS Stage-4 Finding Layer, Analysis Engines, Finding Deduplication, Explainability, Severity/Confidence Scoring, Provenance, Case/Tenant Isolation, Timeline Integration, Persistence, FIR Lifecycle, and API/Analyst Services** has been performed across the repository codebase.

The Stage-4 finding infrastructure (`forensic_analysis/`, `fir/`, `sanitization/`) is **80% Complete and Architecturally Sound**. All 5 domain analysis engines (`network`, `log`, `endpoint`, `memory`, `email`) instantiate `Finding` objects from `forensic_analysis/schemas.py`, adapt them cleanly to `FIRFinding` records in `FIRRepository`, enforce write-time PII redaction and prompt-injection checks, and pass all 508 regression tests.

---

## 2. Component-by-Component Audit Matrix

| Component | Current Status | Actual Repository Evidence | Identified Gap | Risk | Recommended Fix | Files Likely Affected | Verification Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Cross-Engine Normalization** | **PARTIAL** | `forensic_analysis/*_analysis/` | Standard `Finding` schema is used, but engine `metadata` keys vary (`proc_name` vs `process_name`, `ip` vs `dst_ip`). | Downstream consumers encounter inconsistent metadata field names. | Standardize canonical metadata keys across all 5 engines. | `forensic_analysis/*_analysis/*.py` | Unit tests for cross-engine output schema conformity. |
| **Finding Semantic Identity** | **PARTIAL** | `Finding` in `forensic_analysis/schemas.py` | `finding_id` uses random `uuid4()` by default. Does not hash stable semantic fields. | Repeat analysis runs produce duplicate finding records with different IDs. | Derive deterministic finding fingerprint ID `hash(tenant_id, case_id, layer, normalized_fact, sorted(sources))`. | `forensic_analysis/schemas.py` | Unit test for deterministic finding fingerprinting. |
| **Finding Deduplication** | **PARTIAL** | `UnifiedEvidenceStore` in `unified_store.py` | Keyed by `finding_id` UUID; lacks semantic deduplication on fingerprint identity. | Repeated analysis batch runs accumulate duplicate findings. | Implement canonical finding deduplication in `UnifiedEvidenceStore` and `FIRRepository`. | `forensic_analysis/unified_store.py`, `fir/repository.py` | Unit test for finding deduplication. |
| **Provenance Traceability** | **PARTIAL** | `finding_to_fir()` in `schemas.py` | `source_artifact_id` is captured in `Finding`, but omitted from `FIRFinding` top-level schema. | Tracing FIRFinding to original artifact requires querying FCR. | Add `source_artifact_id: Optional[str] = None` to `FIRFinding`. | `fir/schemas.py`, `forensic_analysis/schemas.py` | Unit test for FIR artifact linkage. |
| **Timeline Integration** | **PARTIAL** | `UnifiedTimelineBuilder` in `preprocessing/fcr_engine/timeline.py` | Consumes `Artifact` and `CorrelationRecord` objects, but does not ingest `Finding` objects. | Analyst timeline missing high-level finding events. | Add `Finding` ingestion (`event_type="finding"`) using `finding.timestamp`. | `preprocessing/fcr_engine/timeline.py` | Unit test for finding timeline events. |
| **Analyst Query / API Layer** | **MISSING** | `fir/repository.py`, `unified_store.py` | FIR repository has basic CRUD, but lacks a unified `AnalystFindingService` query/export API layer. | Analyst dashboards must assemble findings, review gates, and timeline events manually. | Implement `AnalystFindingService` in `fir/service.py`. | `fir/service.py` | Unit test for analyst query & export service. |
| **Persistence Idempotency** | **PARTIAL** | `write_finding()`, `insert()` | Relies on `ON CONFLICT (finding_id) DO UPDATE`, which fails when random UUIDs are passed. | Duplicate rows inserted into PostgreSQL `forensic_findings` & `fir_findings`. | Enforce deterministic fingerprint primary keys for SQL `ON CONFLICT DO UPDATE`. | `forensic_analysis/unified_store.py`, `fir/repository.py` | Unit test for SQL persistence idempotency. |

---

## 3. Explicit Pipeline Layer Distinction

$$\text{Artifact (Stage 2)} \longrightarrow \text{Extracted Observable (Stage 2.5)} \longrightarrow \text{FCR (Stage 3)} \longrightarrow \text{Finding / FIRFinding (Stage 4)}$$

1. **Artifact (`preprocessing/schemas.py`)**: Normalized record of raw evidence (e.g. file, log entry, registry value).
2. **Extracted Observable (`preprocessing/schemas.py`)**: Derived atomic IOC or entity extracted from an Artifact (e.g. IP, domain, hash, process name).
3. **Forensic Correlation Record - FCR (`preprocessing/fcr_engine/schemas.py`)**: Rule-based correlation linking $\ge 2$ Artifacts under a specific relationship (`temporal_proximity`, `shared_ioc`, `process_tree`, `network_process`). FCR confidence measures structural correlation strength.
4. **Finding (`forensic_analysis/schemas.py`) & FIRFinding (`fir/schemas.py`)**: Higher-level forensic/security conclusion produced by a deterministic analysis engine, annotated with MITRE ATT&CK mapping, severity, confidence, sanitized fact, and analyst review state (`pending_review`, `analyst_confirmed`, `analyst_rejected`). Finding confidence measures threat detection rule certainty.

---

## 4. Dependency-Aware Implementation Sequence for Phase A.4

- **Sub-Phase A.4.1**: Finding Contract & Cross-Engine Normalization
- **Sub-Phase A.4.2**: Finding Identity & Semantic Deduplication
- **Sub-Phase A.4.3**: Provenance & FCR/Evidence Traceability
- **Sub-Phase A.4.4**: Timeline + Analyst View Integration (`AnalystFindingService`)
- **Sub-Phase A.4.5**: Persistence & Query Integrity
- **Sub-Phase A.4.6**: FIR Review / Export Lifecycle Verification
- **Sub-Phase A.4.7**: Comprehensive Phase A.4 Hardening Test Suite & Real Evidence Verification

---

## 5. Audit Verdict

```
================================================================================
PHASE A.4 REVISED ARCHITECTURAL AUDIT VERDICT
================================================================================
Existing Stage-4 Infrastructure : 80% Complete & Architecturally Sound
Refined Gaps Identified         : 6 Gaps (Cross-engine metadata normalization,
                                  Fingerprint identity dedup, FIR artifact linkage,
                                  Timeline finding events, AnalystFindingService API,
                                  Persistence SQL idempotency)
Current Code Changes Made       : 0 Code Modifications (Strict Audit Phase Only)
Audit Document                  : PHASE_A4_AUDIT_GAP_MATRIX.md
================================================================================
STATUS: REVISED AUDIT COMPLETE (Awaiting Architecture Review Approval)
================================================================================
```
