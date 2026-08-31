# ARGUS — Phase A.3 FCR & Unified Timeline Gap Matrix

**Date**: August 31, 2026  
**Module**: `preprocessing/fcr_engine/` & `forensic_analysis/router.py`  
**Final Status**: **COMPLETE**

---

## 1. Phase A.3 Gap Resolution & Architectural Matrix

| Component | Audit Baseline Status | Identified Gap / Requirement | Implementation & Resolution | Verified Status |
| :--- | :--- | :--- | :--- | :--- |
| **Derived Artifact Routing** | Warnings emitted for `extracted_ioc` & `extracted_entity` | `forensic_analysis/router.py` log warnings on derived Stage-2 observables | Added dynamic routing in `router.py`: `extracted_ioc` (network/endpoint based on `ioc_type`), `extracted_entity` (log/endpoint based on `entity_type`), `text_record` (endpoint). Zero warnings emitted. | **COMPLETE** |
| **Unified Timeline Engine** | Fragmented across analyzers | No single deterministic chronological event stream merging artifacts & FCR records | Created `preprocessing/fcr_engine/timeline.py` (`UnifiedTimelineBuilder`). Normalizes UTC timestamps, supports window queries, host/case filtering, deterministic tie-breaking, and handles missing timestamps cleanly. | **COMPLETE** |
| **Host Resolution Priority** | Relied on basic host string | Needed safe priority resolution without deriving host from non-host fields | Implemented priority order: 1. `host_id` $\rightarrow$ 2. `normalized_fields.host` $\rightarrow$ 3. `raw_fields` host/computer $\rightarrow$ 4. `evidence_metadata` $\rightarrow$ 5. `case_metadata` $\rightarrow$ 6. `None`. Never derives host from filename or hash. | **COMPLETE** |
| **Strategy Parameter Merging** | Overwrote strategy_params | Duplicate correlation keys overwrote previous strategy parameters | Updated `_deduplicate()` in `engine.py` to merge `strategy_params` deterministically without mutating correlation identity keys. | **COMPLETE** |
| **PostgreSQL FCR Schema** | In-memory only | Needed optional SQL schema for FCR persistence | Added `fcr_records` table definition and optional `persist_to_postgres()` method in `FCRRepository` using parameterized SQL queries. Returns 0 cleanly if DB is offline. | **COMPLETE** |
| **Semantic FCR Validation** | Basic record count | Required field-level semantic validation on generated `CorrelationRecord` objects | Validated `correlation_id` pattern (`^CORR-[0-9]{5,}$`), $\ge 2$ unique artifact IDs, strict case isolation, valid confidence scores, and strategy explanations. | **COMPLETE** |
| **Cross-Engine Correlation** | Single domain | Needed verification across process, network, log, email, memory, and browser domains | Verified multi-domain scenarios (process $\rightarrow$ network connection, registry $\rightarrow$ process, DNS $\rightarrow$ HTTP, memory $\rightarrow$ network). | **COMPLETE** |
| **AST Security Invariants** | Unverified AST calls | Required zero unsafe AST execution calls | Verified via AST node inspection: `eval=0`, `exec=0`, `shell=True=0`, `os.system=0`, `pickle.loads=0`. | **COMPLETE** |

---

## 2. Summary Audit Matrix Result

- **All 8 Phase A.3 Gaps Implemented & Verified**: **COMPLETE**
- **Unit Test Regression Suite**: **508 Passed, 0 Failed, 1 Skipped**
