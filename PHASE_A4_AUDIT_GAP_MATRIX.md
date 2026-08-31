# ARGUS — Phase A.4 Architectural Audit Gap Matrix

**Date**: August 31, 2026  
**Audited Layer**: Stage 4 Forensic Finding Layer (`forensic_analysis/`, `fir/`, `sanitization/`)  
**Status**: **AUDIT COMPLETE** (No code modified, awaiting plan review)

---

## 1. Executive Summary

A comprehensive architectural audit of the **ARGUS Stage-4 Finding Layer, Analysis Engines, Finding Deduplication, Explainability, Severity/Confidence Scoring, Provenance, Case/Tenant Isolation, Timeline Integration, and Persistence** has been performed across the repository.

The existing Stage-4 architecture (`forensic_analysis/`, `fir/`, `sanitization/`) is **80% Complete and Architecturally Sound**. All 5 domain analysis engines (`network`, `log`, `endpoint`, `memory`, `email`) exist and execute deterministically. `Finding` objects adapt cleanly to `FIRFinding` records in `FIRRepository`, enforce write-time PII redaction and prompt-injection checks, and pass all 508 regression tests.

---

## 2. Component-by-Component Audit Matrix

| Component | Current Status | Actual Repository Evidence | Identified Gap | Risk | Recommended Fix | Files Likely Affected | Verification Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Finding Schema** | **COMPLETE** | `Finding` in `forensic_analysis/schemas.py` | `finding_id` uses random UUID `uuid4()` by default rather than a deterministic fingerprint key. | Duplicate findings generated across repeat runs. | Add optional deterministic fingerprint key derivation `hash(case_id, layer, fact, source_artifact_id)`. | `forensic_analysis/schemas.py` | Unit tests for fingerprint identity. |
| **FIR Adapter** | **COMPLETE** | `finding_to_fir()` in `schemas.py` | `source_artifact_id` is stored in Finding but omitted from `FIRFinding` top-level schema. | Tracing FIRFinding to original artifact requires querying FCR. | Add `source_artifact_id: Optional[str] = None` to `FIRFinding`. | `fir/schemas.py`, `forensic_analysis/schemas.py` | Unit tests for FIR artifact linkage. |
| **Finding Deduplication** | **PARTIAL** | `UnifiedEvidenceStore` in `unified_store.py` | Keyed by `finding_id` UUID; no semantic deduplication on `(case_id, layer, fact, source_artifact_id)`. | Repeated analysis batch runs store duplicate findings. | Implement canonical finding deduplication in `UnifiedEvidenceStore` and `FIRRepository`. | `forensic_analysis/unified_store.py`, `fir/repository.py` | Unit test for finding deduplication. |
| **Timeline Integration** | **PARTIAL** | `UnifiedTimelineBuilder` in `preprocessing/fcr_engine/timeline.py` | Consumes `Artifact` and `CorrelationRecord` objects, but does not ingest `Finding` objects. | Analyst timeline missing high-level finding events. | Add `Finding` ingestion support (`event_type="finding"`) to `UnifiedTimelineBuilder`. | `preprocessing/fcr_engine/timeline.py` | Unit test for finding timeline events. |
| **Severity & Confidence** | **COMPLETE** | `VALID_SEVERITIES` in `schemas.py` | Analyzers use hardcoded or heuristic severities without a unified scoring policy helper. | Inconsistent severity assignments between engines. | Expose `compute_finding_confidence()` helper in `schemas.py`. | `forensic_analysis/schemas.py` | Unit test for scoring standardization. |
| **Case / Tenant Isolation** | **COMPLETE** | `write_finding()`, `read_findings()`, `insert()` | Strict `WHERE case_id = %s AND tenant_id = %s` enforced across memory and PostgreSQL stores. | None. | Retain strict isolation. | None | Unit test for case isolation. |
| **AST Security Audit** | **COMPLETE** | `test_ast_security_invariants` | `eval=0`, `exec=0`, `shell=True=0`, `os.system=0`, `pickle.loads=0`. | None. | Retain clean AST posture. | None | AST security inspection test. |

---

## 3. Explicit Pipeline Layer Distinction

$$\text{Artifact (Stage 2)} \longrightarrow \text{Extracted Observable (Stage 2.5)} \longrightarrow \text{FCR (Stage 3)} \longrightarrow \text{Finding / FIRFinding (Stage 4)}$$

1. **Artifact (`preprocessing/schemas.py`)**: Normalized record of raw evidence (e.g. file, log entry, registry value).
2. **Extracted Observable (`preprocessing/schemas.py`)**: Derived atomic IOC or entity extracted from an Artifact (e.g. IP, domain, hash, process name).
3. **Forensic Correlation Record - FCR (`preprocessing/fcr_engine/schemas.py`)**: Rule-based correlation linking $\ge 2$ Artifacts under a specific relationship (`temporal_proximity`, `shared_ioc`, `process_tree`, `network_process`).
4. **Finding (`forensic_analysis/schemas.py`) & FIRFinding (`fir/schemas.py`)**: Higher-level forensic/security conclusion produced by a deterministic analysis engine, annotated with MITRE ATT&CK mapping, severity, confidence, sanitized fact, and analyst review state (`pending_review`, `analyst_confirmed`, `analyst_rejected`).

---

## 4. Proposed Sub-Phase Implementation Sequence for Phase A.4

- **Sub-Phase A.4.1**: Canonical Finding Deduplication & Fingerprint Key
- **Sub-Phase A.4.2**: Top-Level Provenance & FIR Artifact Linkage
- **Sub-Phase A.4.3**: Unified Timeline Finding Ingestion
- **Sub-Phase A.4.4**: Severity & Confidence Standardization
- **Sub-Phase A.4.5**: Comprehensive Phase A.4 Hardening Test Suite & Real Evidence Verification

---

## 5. Audit Verdict

```
================================================================================
PHASE A.4 ARCHITECTURAL AUDIT VERDICT
================================================================================
Existing Stage-4 Infrastructure : 80% Complete & Fully Functional
Gaps Identified                 : 5 Gaps (Fingerprint dedup, FIR artifact linkage,
                                  Timeline finding ingestion, Scoring standardization,
                                  API query service)
Current Code Changes Made       : 0 Code Modifications (Audit Phase Only)
Audit Document                  : PHASE_A4_AUDIT_GAP_MATRIX.md
================================================================================
STATUS: AUDIT COMPLETE (Awaiting Plan Approval before Implementation)
================================================================================
```
