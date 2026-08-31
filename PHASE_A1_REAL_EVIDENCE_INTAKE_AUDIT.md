# ARGUS Phase A.1 — Real Evidence Intake Audit

## Dataset
- **Dataset**: `nps-2009-ntfs1` (NTFS File System Test Image Generations)
- **Source**: Digital Corpora (NPS)
- **Local Path**: `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk`
- **Files Expected**: 7
- **Files Found**: 7

---

## Integrity
| File | Size | SHA-256 | Published Hash | Result |
|---|---|---|---|---|
| `narrative.txt` | 665 B | `97c52467f98aff6002595d21d46534cf1205ed7b497b69014cb5973695458241` | NOT_AVAILABLE | NOT_AVAILABLE |
| `ntfs1-gen0.aff` | 277,228 B | `bf0291a0ee8403962f2de8ea93d908088e4265a02438dfb5b1c85efc07037b76` | NOT_AVAILABLE | NOT_AVAILABLE |
| `ntfs1-gen0.E01` | 1,089,252 B | `96e525f53d50f986461151f8e9c07588633215477a6b8a3f744b2eeebe512460` | NOT_AVAILABLE | NOT_AVAILABLE |
| `ntfs1-gen1.aff` | 8,481,452 B | `33528f2d44fed0dac1d96b90b444cf9309207413948bf4c4f685b0332da86cc5` | NOT_AVAILABLE | NOT_AVAILABLE |
| `ntfs1-gen1.E01` | 9,332,369 B | `ed26b63cb37350fba5aaf18f8c871515ff787db98bfa1c5d92b179185168dd6e` | NOT_AVAILABLE | NOT_AVAILABLE |
| `ntfs1-gen2.E01` | 36,083,007 B | `2badead91bef56c80155d7731671ad1d93c08f32cd4ce17566fdf02d5769feea` | NOT_AVAILABLE | NOT_AVAILABLE |
| `ntfs1-gen2.xml` | 2,341,489 B | `efe48e07ed327d3b80f6b208c6dace55e17a0c23636d4cdf831b17a260daaab8` | NOT_AVAILABLE | NOT_AVAILABLE |

---

## Infrastructure
| Component | Path | Current Status | How Phase A Uses It |
|---|---|---|---|
| Evidence Intake | `infrastructure/upload/intake.py` | Active & Functional | Streaming chunked intake write to temporary staging directory |
| Sandbox Validation | `infrastructure/sandbox/intake_validator.py` | Active & Functional | MIME, file size, extension allowlist, and container safety validation |
| Hash & Encryption | `infrastructure/integrity/hash_encrypt.py` | Active & Functional | Streaming SHA-256 integrity seal, AES-256-GCM encryption & RFC 3161 TSA timestamping |
| Metadata & Custody | `infrastructure/custody/metadata_custody.py` | Active & Functional | Append-only custody log recording, format-specific metadata extraction |
| Evidence Store & Audit | `infrastructure/repository/evidence_store.py` | Active & Functional | Case session binding, durable repository storage, Postgres/MinIO fallback |

---

## Case / Tenant
| Check | Result | Notes |
|---|---|---|
| Dedicated Case ID | PASS | Created test case `CASE-PHASEA-NPS-NTFS1` |
| Tenant Isolation | PASS | Bound to tenant `tenant-phasea-nps` |
| Non-Destructive Ingestion | PASS | Production logic left unmodified; test case passed via standard infrastructure pipeline |

---

## Chain of Custody
| Check | Result | Notes |
|---|---|---|
| Original Filename Preserved | PASS | Preserved across all 7 evidence records |
| Original SHA-256 Preserved | PASS | Pre-ingestion and post-ingestion SHA-256 hashes match 100% |
| Evidence ID Generated | PASS | Unique UUID generated for each file |
| Case ID & Tenant ID Attached | PASS | All 7 files attached to `CASE-PHASEA-NPS-NTFS1` & `tenant-phasea-nps` |
| Timestamps Recorded | PASS | Intake timestamp & RFC 3161 TSA timestamp token issued |
| Custody & Audit Events | PASS | Append-only entries logged (`uploaded`, `sandbox_validated`, `hashed`, `encrypted_stored`, `metadata_extracted`, `stored`) |
| Zero File Mutation | PASS | Original raw evidence files in source directory remain untouched |

---

## Repository Persistence
| Check | Result | Notes |
|---|---|---|
| Local Repository Storage | PASS | Saved to `data/repository/CASE-PHASEA-NPS-NTFS1/{evidence_id}/original/` and `/encrypted/` |
| Encrypted Representation | PASS | Chunked AES-256-GCM encrypted file (`.enc`) generated and stored separately |
| PostgreSQL Persistence | UNAVAILABLE | Docker container offline during test; graceful fallback to structured file logs logged warning |
| MinIO Storage | UNAVAILABLE | Docker container offline during test; local repository fallback active |

---

## Parser Capability
| File | Format | Parser | Result | Notes |
|---|---|---|---|---|
| `narrative.txt` | ASCII Text | None | UNSUPPORTED | Text documentation / narrative |
| `ntfs1-gen0.aff` | AFF (Advanced Forensic Format) | None | UNSUPPORTED | Parser gap: ARGUS lacks native `.aff` router binding |
| `ntfs1-gen0.E01` | E01 (Expert Witness / EnCase) | `FilesystemParser` | SUPPORTED | Generation 0 snapshot image |
| `ntfs1-gen1.aff` | AFF (Advanced Forensic Format) | None | UNSUPPORTED | Parser gap: ARGUS lacks native `.aff` router binding |
| `ntfs1-gen1.E01` | E01 (Expert Witness / EnCase) | `FilesystemParser` | SUPPORTED | Generation 1 snapshot image |
| `ntfs1-gen2.E01` | E01 (Expert Witness / EnCase) | `FilesystemParser` | SUPPORTED | Generation 2 snapshot image |
| `ntfs1-gen2.xml` | DFXML (Digital Forensics XML) | None | UNSUPPORTED | Fiwalk DFXML catalog metadata |

### E01 Relationship Analysis
The 3 `.E01` files (`ntfs1-gen0.E01`, `ntfs1-gen1.E01`, `ntfs1-gen2.E01`) represent **three sequential generational snapshots** (`gen0`, `gen1`, `gen2`) of the same `NTFS1` test disk volume created at different points during simulated file system operations (interleaved file writes and fragmentation). They are independent generational disk images, not multi-volume split segments (which would follow `.E01`, `.E02`, `.E03`).

---

## Metadata Handling
| File | Classification | Result | Notes |
|---|---|---|---|
| `narrative.txt` | Evidence Documentation | PASS | Dataset description; contains EFS credentials (`password`). Retained as evidence metadata. |
| `ntfs1-gen2.xml` | DFXML File Catalog | PASS | `fiwalk` XML output for `ntfs1-gen2.raw`; contains file hashes and partition metadata. Retained as evidence metadata. |

---

## Security
| Security Check | Result | Notes |
|---|---|---|
| No Evidence Execution | PASS | Evidence treated strictly as DATA ONLY |
| No Subprocess on Evidence | PASS | Zero subprocess invocation on raw evidence files |
| No Shell Execution | PASS | `shell=True` not used |
| No `eval()` / `exec()` | PASS | No dynamic code execution |
| No Unsafe Deserialization | PASS | Safe JSON/binary parsing |
| No Network Upload | PASS | Evidence contained locally |
| No Unsanitized LLM Calls | PASS | LLM not invoked during infrastructure intake |
| Source Immutability | PASS | All 7 original files untouched (0 bytes altered) |

---

## Failures / Defects
1. **Docker Services Offline**: PostgreSQL (5433) and MinIO (9000) containers were offline during ingestion check. Infrastructure layer successfully executed using local file repository fallback and structured file logging.
2. **Missing Key Env Warning**: `ARGUS_FERNET_KEY` environment variable was not set in shell environment, falling back to ephemeral process key (warning logged).

---

## Unsupported Inputs
1. **`.aff` (Advanced Forensic Format)**: `ntfs1-gen0.aff` and `ntfs1-gen1.aff` returned `UNKNOWN` from `ParserRouter`. ARGUS currently lacks a dedicated `.aff` parser module.
2. **DFXML (`.xml`)**: `ntfs1-gen2.xml` returned `UNKNOWN` from `ParserRouter`. ARGUS does not currently ingest DFXML directly into the evidence routing engine.

---

## Data Integrity Verdict
**PASS** — All 7 source evidence files retained 100% hash identity (SHA-256) before and after ingestion.

---

## Phase A.1 Verdict
**PASS WITH GAPS** — Infrastructure intake, SHA-256 integrity seal, AES-256-GCM encryption, RFC 3161 timestamping, chain of custody logging, and `.E01` parser routing completed with 100% success. Gaps identified in `.aff` format support, DFXML ingestion, and offline Docker backend services.
