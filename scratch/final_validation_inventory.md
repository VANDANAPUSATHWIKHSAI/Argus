# ARGUS — Final Pre-Handoff System Verification Inventory

## 1. Discovered System Architecture & Module Mapping

| System Layer / Component | Module Path | Purpose / Implementation | Key Classes / Functions |
|---|---|---|---|
| **Layer 1: Intake & Custody** | `infrastructure/upload/intake.py` | Streaming chunked write, path traversal defense, custody logging | `upload_evidence()` |
| | `infrastructure/sandbox/intake_validator.py` | MIME, extension allowlist & security checks | `IntakeValidator.validate_file()` |
| | `infrastructure/integrity/hash_encrypt.py` | SHA-256 integrity seal & AES-256-GCM encryption | `IntegritySeal` |
| | `infrastructure/custody/metadata_custody.py` | Append-only custody audit logging | `CustodyLogger.log_event()` |
| | `infrastructure/repository/evidence_store.py` | Durable evidence store (Postgres / MinIO / Local fallback) | `EvidenceRepository` |
| **Layer 2: Router & Parsers** | `preprocessing/router.py` | Layered detection router (magic bytes, path, ext) for 42 sources | `ParserRouter.determine_routing()`, `ParserRouter.route()` |
| | `preprocessing/parsers/memory_parser.py` | Volatility 3 multi-plugin memory dump parser | `MemoryParser.parse()` |
| | `preprocessing/parsers/filesystem_parser.py` | Disk image & E01/AFF Sleuth Kit parser | `FilesystemParser.parse()` |
| **Layer 3: Normalization** | `preprocessing/normalizer.py` | Canonical `Artifact` schema normalization (UTC timestamps) | `Normalizer.normalize()` |
| **Layer 4: Artifact Extractor** | `preprocessing/artifact_extractor/extractor.py` | Deterministic ioc-finder, YARA & CyNER DeBERTa-v3 NER | `ArtifactExtractor.extract_artifacts()` |
| **Layer 5: FCR Engine** | `preprocessing/fcr_engine/engine.py` | Rule-based Forensic Correlation Records (temporal, shared IOC, process) | `FCREngine.correlate()` |
| **Layer 6: Evidence Consolidation** | `preprocessing/evidence_consolidation/consolidation.py` | Unified Artifact (UAI) generation, deduplication, conflict preservation | `EvidenceConsolidationEngine.consolidate()` |
| **Layer 7: Analysis Engines** | `forensic_analysis/memory_analysis/memory_engine.py` | Memory domain analysis (7 sub-analyzers: process, DLL, network, injection, rootkit, credential, timeline) | `MemoryAnalysisEngine.analyze()` |
| | `forensic_analysis/endpoint_analysis/` | Endpoint forensic analyzers | `EndpointAnalysisEngine` |
| | `forensic_analysis/log_analysis/` | Log forensic analyzers | `LogAnalysisEngine` |
| | `forensic_analysis/email_analysis/` | Email forensic analyzers | `EmailAnalysisEngine` |
| | `forensic_analysis/network_analysis/` | PCAP / network analyzers | `NetworkAnalysisEngine` |
| **Layer 8: Sanitization Gateway** | `sanitization/gateway.py` | PII scrubbing, DeBERTa-v3 prompt injection detector, XML wrapping | `SanitizationGateway.sanitize_finding()` |
| **Layer 9: FIR Repository & DB** | `fir/repository.py` | Authoritative `fir_findings` table store with PostgreSQL persistence | `FIRRepository.insert()`, `FIRRepository.get_by_id()` |
| **API Backend** | `api/main.py` & `api/routes/` | FastAPI REST API endpoints (`/cases`, `/evidence`, `/query`, `/reports`) | FastAPI app |
| **Frontend UI** | `frontend/app.py` | Streamlit analyst workbench dashboard | Streamlit app |
| **Docker Infrastructure** | `docker-compose.yml` | PostgreSQL (5433), MinIO (9000), Neo4j (7474/7687), Qdrant (6333), ClamAV (3310) | Docker Compose services |

---

## 2. Actual Real Evidence Catalog

- **Dataset**: `nps-2009-ntfs1` (NTFS File System Test Image Generations)
- **Location**: `c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk`
- **Classification**: **REAL DISK IMAGE EVIDENCE** (No raw RAM dump file present in raw evidence; memory analysis validated separately via Volatility 3 fixtures).
- **Files**:
  1. `narrative.txt` (665 B) — Text documentation / credentials
  2. `ntfs1-gen0.aff` (277 KB) — Generation 0 AFF disk image (Blocked: missing `libaff` in `fls.exe`)
  3. `ntfs1-gen0.E01` (1.08 MB) — Generation 0 E01 disk image (Supported)
  4. `ntfs1-gen1.aff` (8.48 MB) — Generation 1 AFF disk image (Blocked: missing `libaff` in `fls.exe`)
  5. `ntfs1-gen1.E01` (9.33 MB) — Generation 1 E01 disk image (Supported)
  6. `ntfs1-gen2.E01` (36.08 MB) — Generation 2 E01 disk image (Supported)
  7. `ntfs1-gen2.xml` (2.34 MB) — Digital Forensics XML metadata catalog (Supported)

---

## 3. Discovered Test Suites & Scope

- Unit Test Suite: `tests/unit/` and top-level `test_*.py` files (380+ tests)
- Integration Test Suite: `tests/integration/`
- Pytest Configuration: `pytest.ini`
- Performance / Benchmark Suites: `test_preprocessing_parsers.py`
