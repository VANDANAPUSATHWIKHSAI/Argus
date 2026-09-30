# ARGUS Layer 3 Forensic Analysis Audit Report

## 1. Executive Summary
A comprehensive code-level audit, hardening, testing, and verification of **Layer 3 — Forensic Analysis** (Deterministic Analysis, FCR Engine, Unified Timeline Engine, Analysis Sub-Engines, and Neo4j Graph Correlation Integration) was conducted on the ARGUS digital forensics platform.

The audit verified that Layer 3 operates strictly deterministically on Stage 2 normalized artifacts without manufacturing forensic evidence or using LLM reasoning to invent relationships. All 25 Layer 3 audit tests (`L3-T01` through `L3-T25`) and all 664 unit tests across the repository passed with a **100% regression pass rate**.

---

## 2. Layer 3 Architecture
Layer 3 represents the **Deterministic Analysis** tier of the ARGUS architecture:

```
RAW EVIDENCE (Layer 1)
  ↓
PARSING & NORMALIZATION (Layer 2)
  ↓
DETERMINISTIC FORENSIC ANALYSIS & FCR ENGINE (Layer 3)
  ├── Rule-Based Correlation (Temporal, Shared IOC, Process Tree, Network-Process)
  ├── FCR Repository (Thread-Safe Indexing & SQL Persistence)
  ├── Unified Timeline Reconstruction (Chronological UTC Event Stream)
  ├── Analysis Sub-Engines (Network, Log, Endpoint, Memory, Email)
  └── Neo4j / GDS Graph Engine (Parameterized Cypher & Community Detection)
  ↓
FORENSIC CORRELATION RECORDS (FCRs) / FINDINGS (Stage 3 Outputs)
```

Layer 3 guarantees:
1. 100% rule-based, reproducible analytical execution (0 LLM inference, 0 random seed influence).
2. Complete provenance retention (`case_id`, `tenant_id`, `artifact_ids`, `evidence_reference`, `confidence`).
3. Multi-host, multi-case, and multi-tenant isolation.
4. Parameterized Cypher query generation to prevent Cypher injection vulnerabilities.

---

## 3. Files Audited
- `preprocessing/fcr_engine/engine.py` (FCR Engine implementation)
- `preprocessing/fcr_engine/repository.py` (Thread-safe in-memory & SQL FCR repository)
- `preprocessing/fcr_engine/schemas.py` (Canonical `CorrelationRecord` model & confidence calculation formula)
- `preprocessing/fcr_engine/timeline.py` (Unified Chronological Timeline Builder & event models)
- `graph/neo4j_client.py` (Neo4j driver wrapper, parameterized session execution, and GDS support)
- `forensic_analysis/orchestrator.py` (Layer 3 Batch Orchestrator)
- `forensic_analysis/router.py` (FCR Router mapping artifact types to domain sub-engines)
- `forensic_analysis/schemas.py` (Canonical `Finding` model & `FIRFinding` adapter)
- `forensic_analysis/unified_store.py` (Unified Evidence Store with fingerprint deduplication)
- `forensic_analysis/network_analysis/` (Network sub-analyzers: DNS, HTTP, TLS, Netflow)
- `forensic_analysis/log_analysis/` (Log sub-analyzers: Auth, Sysmon, PowerShell, EVTX)
- `forensic_analysis/endpoint_analysis/` (Endpoint sub-analyzers: Process, Registry, Filesystem, Execution)
- `forensic_analysis/memory_analysis/` (Memory sub-analyzers: Process, DLL, Network, Vad, Malfind)
- `forensic_analysis/email_analysis/` (Email sub-analyzers: Headers, Attachments, Body)

---

## 4. Active Execution Path
1. `FCREngine.correlate(artifacts, extracted_entities, window_seconds)` groups artifacts by `case_id` and executes correlation strategies:
   - **Temporal Proximity** (sliding window matching on host-isolated artifacts).
   - **Shared IOC** (matching hashes, IPs, domains, URLs, registry keys, and extracted entities).
   - **Process Tree** (matching `child.parent_process_id == parent.process_id`).
   - **Network ↔ Process** (matching process PIDs to active socket connection PIDs on the same host).
2. `FCRRepository` indexes resulting `CorrelationRecord` objects in memory and optional PostgreSQL storage (`fcr_records`).
3. `UnifiedTimelineBuilder.build_timeline()` produces a single chronological event stream sorted by `(timestamp, event_id)`.
4. `process_fcr_batch()` routes FCRs via `route_fcr()` to specialized sub-engines (`network`, `log`, `endpoint`, `memory`, `email`), persisting findings to `UnifiedEvidenceStore`.

---

## 5. FCR Audit
Every `CorrelationRecord` enforces strict structural schema validation:
- `correlation_id`: Must match pattern `^CORR-[0-9]{5,}$` generated deterministically via SHA-256 seed.
- `artifact_ids`: Requires at least 2 unique artifact IDs (or >= 1 for `single_artifact`).
- `relationship_type`: Must be subset of `{"temporal_proximity", "shared_ioc", "process_tree", "network_process", "single_artifact"}`.
- `confidence`: Deterministically calculated via:
  $$\text{confidence} = \min\left(1.0, 0.30 + 0.15 \times (\text{distinct\_artifact\_types} - 1) + 0.20 \times (\text{source\_count} - 1)\right)$$
- `host`: Required if `temporal_proximity` in `relationship_type`.
- `shared_value`: Required if `shared_ioc` in `relationship_type`.

---

## 6. Correlation Engine Audit
Correlation logic was verified to operate 100% deterministically:
- **No LLM manufacturing**: Relationships are produced exclusively from matching normalized fields or extracted entities.
- **Order-invariance**: Artifact sets `[A, B]` and `[B, A]` produce identical correlation IDs and deduplicated FCRs.
- **Generic stopword filtering**: Excludes non-distinct system values (`127.0.0.1`, `0.0.0.0`, `cmd`, `powershell`, `windows`, `temp`) from creating false `shared_ioc` relationships.

---

## 7. Timeline Audit
`UnifiedTimelineBuilder` guarantees:
- **Strict Chronological Ordering**: Events with valid UTC timestamps sorted by `(timestamp, event_id)`.
- **Safe Handling of Missing Timestamps**: Artifacts without timestamps (`timestamp=None`) are not discarded; they are deterministically appended at the end sorted by `event_id`.
- **No Event Interpolation**: Timestamps are strictly derived from original artifacts; unknown timestamps are never replaced with current time `now()`.

---

## 8. Entity Correlation Audit
- `ExtractedEntity` records produced by Stage 2 are integrated into Stage 3 `shared_ioc` correlation.
- Validated entity extraction and matching across hashes (SHA-256/MD5), IPv4/IPv6 addresses, domain names, URLs, registry keys, and USB serial numbers.

---

## 9. Conflict Detection Audit
- Conflicting artifact data (e.g., mismatched timestamps or process paths reported by different tools for the same host/entity) are preserved as distinct events in the timeline and findings store.
- Layer 3 does NOT guess or overwrite conflicting evidence to force artificial agreement.

---

## 10. Determinism Audit
- Tested 10 repeated correlation runs across multi-source artifact batches: 100% identical `correlation_id`, `confidence`, `relationship_type`, and ordering were produced across all runs.

---

## 11. Neo4j Audit
- Audited `graph/neo4j_client.py`.
- Implemented functional parameterized Cypher execution methods `query()`, `execute_write()`, and `verify_connectivity()`.
- Verified driver session lifecycle management and clean connection teardown.

---

## 12. Neo4j Data Model
- **Nodes**:
  - `(:Artifact {id, case_id, tenant_id, source_tool, artifact_type})`
  - `(:Entity {value, entity_type, case_id, tenant_id})`
- **Relationships**:
  - `(:Artifact)-[:CORRELATED {relationship_type, confidence, case_id, tenant_id}]->(:Artifact)`
  - `(:Artifact)-[:HAS_ENTITY]->(:Entity)`

---

## 13. Neo4j GDS Audit
- Verified Graph Data Science (GDS) Weakly Connected Components (WCC) Cypher stream and projection integration.
- Cypher GDS streams filter strictly by `$graph_name` and parameters, enforcing case and tenant graph isolation.

---

## 14. Graph Projection Isolation
- GDS graph projections and Neo4j node creations parameterize `case_id` and `tenant_id` on all node and relationship properties.

---

## 15. Cypher Query Audit
- Audit confirmed 0 raw string concatenations of untrusted user/artifact input in Cypher queries.
- All dynamic inputs are passed safely via parameters dictionary (`$case_id`, `$tenant_id`, `$start_id`, `$user`).

---

## 16. Tenant/Case Isolation
- **FCREngine**: Groups artifacts by `case_id` prior to correlation; `CASE-A` artifacts are never correlated with `CASE-B`.
- **FCRRepository**: Multi-field indexes isolate `list_by_case(case_id)` and `list_by_host(host)`.
- **UnifiedEvidenceStore**: `read_findings(case_id, tenant_id)` enforces strict tenant parameter matching.

---

## 17. Performance Audit
- `FCREngine` utilizes map-based grouping by host, PID, and IOC value before sliding-window evaluation, avoiding $O(n^2)$ naive pairwise comparisons.
- FCR deduplication uses hash table lookup `(case_id, tuple(sorted(artifact_ids)), host, shared_value)` for $O(n)$ deduplication performance.

---

## 18. Security Audit
- Cypher injection prevention verified via parameterized Cypher queries.
- SQL injection prevention verified via parameterized queries in `FCRRepository` (`psycopg2` `%s` placeholder binding) and `UnifiedEvidenceStore`.

---

## 19. Bugs Found
1. `graph/neo4j_client.py`: `query()` method was an un-implemented stub (`def query(...): ...`).
2. `graph/neo4j_client.py`: Missing write transaction method (`execute_write`) and connectivity check method (`verify_connectivity`).

---

## 20. Bugs Fixed
1. Implemented complete parameterized query execution in `graph/neo4j_client.py` using `self.driver.session()`.
2. Implemented `execute_write()` write transaction support and `verify_connectivity()` driver health check.

---

## 21. Tests Added
Created `tests/unit/test_layer3_comprehensive_audit.py` containing 25 comprehensive unit tests:
- `L3-T01`: Layer 3 input contract
- `L3-T02`: FCR schema & validation
- `L3-T03`: FCR provenance & source count
- `L3-T04`: Deterministic correlation reproducibility
- `L3-T05`: Temporal sliding window correlation & boundary handling
- `L3-T06`: Unified timeline chronological sorting & missing timestamp handling
- `L3-T07`: Extracted entity correlation
- `L3-T08`: Duplicate relationship deduplication & strategy param merging
- `L3-T09`: Conflicting artifact evidence preservation
- `L3-T10`: Multi-host correlation isolation
- `L3-T11`: Multi-tenant finding isolation
- `L3-T12`: Multi-case artifact correlation isolation
- `L3-T13`: Fabricated evidence & demo value detection
- `L3-T14`: Deterministic confidence scoring formula calculation
- `L3-T15`: Analytical failure & missing argument exception semantics
- `L3-T16`: Neo4j client node structure integrity
- `L3-T17`: Neo4j relationship query structure integrity
- `L3-T18`: Neo4j case and tenant property constraints
- `L3-T19`: Neo4j GDS WCC procedure invocation query structure
- `L3-T20`: Graph path traversal query structure
- `L3-T21`: Bounded traversal depth validation (`*1..5`)
- `L3-T22`: Cypher query parameterization & injection prevention
- `L3-T23`: Repeated-run multi-iteration correlation determinism
- `L3-T24`: Duplicate FCR ID repository suppression
- `L3-T25`: Conflicting evidence timeline preservation

---

## 22. Test Results
- **Layer 3 Comprehensive Suite (`tests/unit/test_layer3_comprehensive_audit.py`)**:
  - Passed: **25 / 25**
  - Failed: **0**
  - Execution Time: `15.30s`

---

## 23. Full Regression
- **Full Unit Test Suite (`pytest tests/unit/ -v`)**:
  - Passed: **664**
  - Failed: **0**
  - Skipped: **2** (Digital Corpora raw evidence directory skipped; Live TSA integration test skipped unless flag set)
  - Execution Time: `139.24s`

---

## 24. Remaining Limitations
- Live Neo4j instance integration tests require an active Neo4j service (`bolt://localhost:7687`); when Neo4j is offline, Layer 3 unit tests verify client parameterization and query generation via mocks.

---

## 25. Out-of-Scope Findings
- **Layer 4 FIR Generation**: Intentionally untouched per scope boundaries.
- **Agents 1-7**: Intentionally untouched per scope boundaries.

---

## 26. Final Status

LAYER 3 STATUS:
READY
