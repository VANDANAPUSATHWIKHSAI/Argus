# ARGUS Layer 1 Infrastructure Audit

## 1. Executive Summary
A comprehensive code-level audit, hardening, and verification of ARGUS **Layer 1 — Infrastructure / Evidence Intake** was performed. Layer 1 serves as the foundational evidence intake engine responsible for sandboxed validation, cryptographic SHA-256 integrity calculation, AES-256-GCM encryption at rest, RFC 3161 trusted timestamping, immutable chain of custody tracking, tenant-isolated storage, and structured audit logging. All 79 unit and integration tests across the Layer 1 suite executed with a **100% pass rate**.

---

## 2. Layer 1 Architecture Found
The active implementation is housed strictly in the root `/infrastructure` package and `/api/routes/evidence.py`. The pipeline consists of 5 deterministic, sequential stages:
1. **Intake & Upload** (`infrastructure/upload/intake.py`): Chunked 64KB streaming write to temporary intake path, path traversal sanitization, UUID assignment.
2. **Sandboxed Intake Validation** (`infrastructure/sandbox/intake_validator.py`): Size limits, extension allowlisting, archive/zip bomb recursive detection, PE magic byte checks, read-only Alpine Docker container containment, and ClamAV malware scanning.
3. **SHA-256 Integrity & AES-256-GCM Encryption** (`infrastructure/integrity/hash_encrypt.py` & `timestamp_service.py`): Single-pass SHA-256 hashing and AES-256-GCM encryption, post-encryption GCM streaming verification, and RFC 3161 TimeStampReq token issuance.
4. **Metadata Extraction & Custody** (`infrastructure/custody/metadata_custody.py`): Format-specific metadata parsing, append-only custody log entry generation.
5. **Durable Repository Storage & Audit** (`infrastructure/repository/evidence_store.py`): Dual storage of original immutable bytes and encrypted representation (local repository or MinIO buckets), tenant-isolated PostgreSQL database persistence, and structured audit logging (`audit_logger.py`).

---

## 3. Evidence Intake Audit
- **Upload Flow**: Ingestion receives streaming raw bytes via FastAPI (`POST /evidence/upload`) or function invocation (`upload_evidence`).
- **IDs & Association**: Every evidence file receives a unique `evidence_id` (UUID v4) while strictly preserving `case_id` (e.g. `ARGUS_01`) and `tenant_id`.
- **Filename Handling**: Filenames are sanitized via `sanitize_segment()` and `os.path.basename()` after unquoting to eliminate directory traversal.
- **Partial/Failed Uploads**: Partial or zero-byte uploads raise explicit HTTP 400 exceptions; failed uploads set `status = FAILED` and log explicit custody failure reasons without creating misleading success records.

---

## 4. File Security Audit
- **Path Traversal Prevention**: Server-side validation via `sanitize_segment()` rejects `..`, `/`, `\`, and null bytes `\x00` in both raw and URL-unquoted representations.
- **API Endpoint Protection**: Updated `api/routes/evidence.py` to sanitize `relative_path` and `file.filename` using `os.path.basename()` and `.resolve().relative_to(resolved_temp_dir)` bounds verification, blocking nested traversal tricks (e.g., `....//etc/passwd`).
- **Symlink Protection**: Symlinks are explicitly detected and rejected (`os.path.islink`) during stage 2 validation.

---

## 5. Sandbox Audit
- **Isolation Controls**:
  - **Docker Containment**: Read-only bind mount (`/evidence/file`), networking disabled (`network_disabled=True`), execution as non-root user `nobody`, 100MB RAM ceiling (`mem_limit="100m"`), 0.5 CPU quota (`nano_cpus=500_000_000`), 30-second execution timeout.
  - **Data-Only Execution**: The container script reads raw bytes (`dd`) and hex-dumps headers (`od`) for inspection without ever invoking `eval`, `sh`, or executing evidence bytes.
  - **ClamAV Integration**: Network socket scan via `pyclamd`; flags and rejects files triggering `virus_detected`.

---

## 6. SHA-256 Integrity Audit
- **Deterministic Hashing**: Hashing is performed directly over the original byte stream using `hashlib.sha256()` in a single pass alongside GCM encryption.
- **Integrity Seal**: The resulting SHA-256 hexdigest is stored in `evidence.sha256_hash` and recorded in custody log and audit log entries.
- **Verification**: Post-encryption GCM streaming decryption verifies that decrypted bytes produce the exact expected SHA-256 before declaring `status = HASHED`.

---

## 7. Encryption Audit
- **AES-256-GCM**: Encryption uses chunked AES-256-GCM with a 4-byte random salt and 12-byte per-chunk nonces (`salt + chunk_idx`).
- **Key Security**: Encryption key loaded from environment variable `ARGUS_FERNET_KEY`. In production (`APP_ENV=production`), startup fails with `RuntimeError` if the key is missing. Ephemeral per-process keys are restricted to dev/testing environments.
- **Storage Isolation**: The encrypted representation (`.enc`) is saved to a distinct directory (`.../encrypted/`) separate from original raw evidence (`.../original/`).

---

## 8. RFC 3161 Timestamping Audit
- **ASN.1 DER Structure**: `build_rfc3161_request_bytes()` constructs standard RFC 3161 `TimeStampReq` over SHA-256 digest (OID `2.16.840.1.101.3.4.2.1`).
- **TSA Integration**: HTTP POST to TSA service (`https://freetsa.org/tsr` or configured `ARGUS_TSA_URL`).
- **Production Fail-Closed**: In production environment (`APP_ENV=production`), TSA unreachability or response error sets `status = FAILED` and raises `RuntimeError`. Mock fallback is strictly restricted to dev/test environments.
- **Verification**: `verify_rfc3161_timestamp()` verifies token presence and SHA-256 digest alignment.

---

## 9. Metadata Audit
- **Fields Extracted**: `evidence_id`, `case_id`, `tenant_id`, `original_filename`, `size_bytes`, `mime_type`, `sha256_hash`, `upload_timestamp`, `uploaded_by`, `encrypted`, `original_repository_path`, `encrypted_repository_path`.
- **No Inventions**: Missing metadata is left `None` or omitted rather than fabricated.

---

## 10. Chain-of-Custody Audit
- **Append-Only Design**: `evidence.custody_log` is represented as an append-only list of immutable `CustodyLogEntry` schemas. Past entries are never modified or overwritten.
- **Lifecycle Actions Tracked**: `uploaded`, `sandbox_validated`, `sandbox_rejected`, `hashed`, `encrypted_stored`, `timestamp_requested`, `timestamped`, `metadata_extracted`, `original_stored`, `stored`.

---

## 11. Case ID Audit
- **Non-UUID Case Identifiers**: Non-UUID human-readable case IDs (e.g. `ARGUS_01`, `ARGUS_L1_01`) are supported throughout intake, repository directory structures, log entries, and database queries.

---

## 12. Tenant Isolation Audit
- **Backend Boundary**: All repository queries (`get_case_session`, `list_cases`, `close_case`, `get_evidence`, `list_evidence_by_case`) enforce tenant boundary isolation at the SQL query layer (`WHERE tenant_id = %s`).
- **Storage Isolation**: Local repository paths and MinIO bucket object keys embed `tenant_id` and `case_id` (`data/repository/{case_id}/{evidence_id}/`).

---

## 13. Original Evidence Immutability Audit
- **Read-Only Preservation**: Original uploaded evidence bytes are saved to `original/{filename}` and set to read-only.
- **No Parser Mutations**: Parsers operate strictly on temporary copies or read-only streams. Original file size and SHA-256 hash remain completely unchanged.

---

## 14. Audit Logging Audit
- **Structured Audit Logging**: Tenant-isolated file logger (`infrastructure/audit_logger.py`) logs structured JSON audit records for case creation, intake, sandbox results, integrity seals, metadata extraction, and storage events.
- **Secret Protection**: Passwords, Fernet/GCM encryption keys, JWT tokens, and raw evidence content are omitted from audit log payloads.

---

## 15. Failure Handling Audit
- **Fail-Closed Semantics**: Exceptions in hashing, encryption, sandbox validation, or TSA timestamping immediately transition `evidence.status` to `FAILED` and raise explicit exceptions. No silent try/except swallows errors.

---

## 16. Transaction / Partial Failure Audit
- **Cleanup on Failure**: Temp files and failed `.enc` files are cleaned up via `try...finally` or `os.remove()` when errors occur during stage execution.

---

## 17. Resource Limit Audit
- **File Size Ceiling**: Configurable `ARGUS_MAX_FILE_SIZE_BYTES` (default 10GB).
- **Archive Bomb Protection**: `check_archive_bomb()` enforces a 100x max compression ratio limit on `.zip`, `.tar`, `.tgz`, `.gz`.
- **Sandbox Limits**: Container restricted to 100MB RAM and 0.5 CPU.

---

## 18. Duplicate Evidence Audit
- **Independent Identity**: Duplicate file uploads receive unique `evidence_id` values and distinct storage paths while preserving identical SHA-256 hashes and provenance records. No silent merging occurs.

---

## 19. Obsolete Implementation Audit
- **Starter Directory Status**: `argus_infrastructure_starter(1)` was audited and confirmed to be unimported and unreferenced across the codebase.
- **Action Taken**: Added `NOTICE_HISTORICAL_REFERENCE.md` inside `argus_infrastructure_starter(1)` marking it strictly as a historical prototype, ensuring developer clarity without destructive deletion.

---

## 20. Tests Executed
The test suite consists of 6 test modules covering unit, security, and integration scenarios:
1. `test_infra_and_sanitization.py` (5 tests)
2. `test_infrastructure_fixes.py` (5 tests)
3. `tests/unit/test_layer1_immutability.py` (7 tests)
4. `tests/unit/test_layer1_repair3.py` (25 tests)
5. `tests/unit/test_rfc3161_timestamping.py` (17 tests)
6. `tests/unit/test_layer1_comprehensive_audit.py` (20 tests: L1-T01 through L1-T20)

---

## 21. Test Results
- **Total Tests**: 79
- **Passed**: 79
- **Failed**: 0
- **Pass Rate**: 100%

---

## 22. Issues Found
1. **Path Traversal Vulnerability in `api/routes/evidence.py`**: Upload endpoint used basic `relative_path.replace("..", "")`, vulnerable to `....//` nested traversal.
2. **Starter Prototype Ambiguity**: `argus_infrastructure_starter(1)` contained old stub code that had potential to confuse developers.

---

## 23. Fixes Applied
1. **Hardened `api/routes/evidence.py`**: Added URL unquoting, `os.path.basename()`, and `.resolve().relative_to(resolved_temp_dir)` verification to prevent path traversal via filename or `relative_path`.
2. **Marked Starter Directory**: Created `argus_infrastructure_starter(1)/NOTICE_HISTORICAL_REFERENCE.md` documenting its historical reference status.
3. **Comprehensive Test Suite Added**: Created `tests/unit/test_layer1_comprehensive_audit.py` covering tests L1-T01 through L1-T20.

---

## 24. Files Modified
1. `api/routes/evidence.py` — Hardened upload path traversal validation.
2. `argus_infrastructure_starter(1)/NOTICE_HISTORICAL_REFERENCE.md` — Marked starter prototype directory as historical.
3. `tests/unit/test_layer1_comprehensive_audit.py` — Created comprehensive L1-T01 to L1-T20 test suite.
4. `LAYER1_INFRASTRUCTURE_AUDIT_REPORT.md` — Created audit report document.

---

## 25. Downstream Issues Observed But Not Modified
- **Layer 2 Preprocessing / Parsers**: Observed minor handling differences in EVTX and Volatility parser stubs when raw memory dumps contain non-standard headers. Intentionally untouched per Layer 1 scope boundaries.
- **Layer 3 Correlation / FIR**: Intentionally untouched.

---

## 26. Remaining Limitations
- **Live TSA Connectivity**: RFC 3161 live network calls to `freetsa.org` require outbound internet access. When offline or unreachable in dev/test mode, deterministic mock fallback is enabled; production mode correctly fails closed if unreachable.

---

## 27. Final Layer 1 Status

    READY

The ARGUS Layer 1 Infrastructure / Evidence Intake backend service is fully audited, hardened, verified, and passing all 79 tests.
