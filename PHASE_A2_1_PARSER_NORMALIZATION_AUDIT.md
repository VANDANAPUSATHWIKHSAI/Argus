# ARGUS — Phase A.2.1 Parser & JSON Normalization Audit Report

**Date**: August 31, 2026  
**Audited Schema**: `preprocessing/schemas.py` (`Artifact`, `NormalizedFields`)  
**Router**: `preprocessing/router.py`  
**Parser Architecture**: 35 Implemented Parsers (`preprocessing/parsers/`)

---

## 1. Canonical Schema Verification

All parsers produce standard `Artifact` records containing a structured `NormalizedFields` payload.

### `Artifact` Root Fields
- `evidence_id`: String (UUID linking back to raw evidence record in PostgreSQL/MinIO)
- `source_tool`: String (e.g. `tsk`, `evtxecmd`, `volatility3`, `dpkt`, `dfxml_fiwalk`, `narrative_text`)
- `artifact_type`: String (e.g. `file_record`, `evtx_record`, `process_memory`, `network_packet`, `text_record`)
- `timestamp`: Timezone-aware UTC `datetime` object
- `timestamp_type`: String (`modified`, `accessed`, `created`, `recorded`, `ingest`)
- `event_summary`: String (Human-readable event overview)
- `parser_version`: String (Version of tool/parser producing the artifact)
- `raw_fields`: Dictionary (Complete untruncated raw output key-value map)
- `normalized_fields`: `NormalizedFields` object

### `NormalizedFields` Payload
| Field Name | Type | Coverage & Description |
| :--- | :--- | :--- |
| `timestamp` | `Optional[str]` | ISO-8601 UTC timestamp string |
| `event_type` | `Optional[str]` | Standardized event categorization |
| `process_id` | `Optional[int]` | PID |
| `parent_process_id` | `Optional[int]` | PPID |
| `process_name` | `Optional[str]` | Binary name |
| `command_line` | `Optional[str]` | Command line execution string |
| `user_name` | `Optional[str]` | Username / SID |
| `host_name` | `Optional[str]` | Hostname / ComputerName |
| `source_ip` | `Optional[str]` | Source IPv4/IPv6 address |
| `destination_ip` | `Optional[str]` | Destination IPv4/IPv6 address |
| `source_port` | `Optional[int]` | Source TCP/UDP port |
| `destination_port` | `Optional[int]` | Destination TCP/UDP port |
| `protocol` | `Optional[str]` | Transport protocol (`TCP`, `UDP`, `ICMP`) |
| `domain` | `Optional[str]` | Domain / FQDN |
| `url` | `Optional[str]` | HTTP/HTTPS URL |
| `file_path` | `Optional[str]` | Absolute file path |
| `file_name` | `Optional[str]` | File basename |
| `hash` | `Optional[str]` | Cryptographic hash (`SHA-256`, `MD5`) |
| `registry_key` | `Optional[str]` | Registry hive key path |
| `registry_value` | `Optional[str]` | Registry value name & content |
| `email_from` | `Optional[str]` | Sender email address |
| `email_to` | `Optional[str]` | Recipient email address |
| `email_subject` | `Optional[str]` | Subject line |
| `attachment_hash` | `Optional[str]` | Email attachment SHA-256 |
| `rule_name` | `Optional[str]` | Downstream rule classification key |

---

## 2. Timestamp Semantics & Preservation Rules

1. **Source Evidence Timestamps Preserved**: Timestamps embedded within raw evidence files (e.g. NTFS MACB times, EVTX SystemTime, PCAP epoch timestamps) are preserved in `raw_fields` and mapped to `Artifact.timestamp`.
2. **Collection/Ingest Timestamps Separated**: Ingestion time is stored explicitly in `timestamp_type="ingest"` or metadata; it NEVER overwrites source timestamps.
3. **UTC Normalization**: All timestamps are converted deterministically to timezone-aware UTC (`tz=timezone.utc`).
4. **Timezone Safety**: Unknown timezones are NOT silently treated as local time; where offset is missing, UTC is assumed with explicit metadata flags.
5. **Timestamp Precision**: Sub-second / microsecond precision is retained where supported by the raw format.

---

## 3. Provenance Preservation Hierarchy

Every record parsed by ARGUS maintains an unbroken chain of custody:

$$\text{Case Session} \longrightarrow \text{Evidence ID} \longrightarrow \text{Raw File} \longrightarrow \text{Parser / Tool} \longrightarrow \text{Normalized Artifact}$$

- `evidence_id`: Primary FK linking back to evidence metadata table in PostgreSQL.
- `source_tool`: Identifier of binary/tool used (`fls`, `evtxecmd`, `volatility`, etc.).
- `parser_version`: Exact version string recorded from `config/tool_versions.py`.
- `line_offset` / `raw_fields`: Raw byte/line offsets retained for auditability.

---

## 4. Failure Safety & Malformed Input Audit

Parsers were subjected to stress tests against invalid, corrupt, or adversarial inputs:
- **Empty Files**: Gracefully returns `[]` artifacts without throwing unhandled exceptions.
- **Truncated / Corrupt Binary Headers**: Caught by parser error wrappers (`TSKExecutionError`, `ParserError`, `UnicodeDecodeError`) and flagged in status.
- **Attacker-Controlled Strings**: Command-line injection patterns in evidence text remain strictly inert strings in `raw_fields` and `NormalizedFields` (no shell execution).
- **Case Isolation**: Parsing errors on a single file do NOT crash the batch pipeline or impact other evidence files.

---

## 5. Preprocessing AST Security Audit

AST security audit scan across `argus/preprocessing/`:
```
eval() calls           : 0
exec() calls           : 0
shell=True calls       : 0
os.system() calls      : 0
pickle.loads() calls   : 0
```
- **Result**: **100% CLEAN** (All external forensic binaries run via list-argument `subprocess.run(cmd, shell=False)`).

---

## 6. Cross-Layer Contract Verification

The output produced by Phase A.2.1 parsers (`list[Artifact]`) was verified against the contract requirements for the downstream **Artifact Extraction** layer:
- `file_path`, `file_name`, and `hash` fields populated for file artifacts.
- Process attributes (`process_id`, `parent_process_id`, `process_name`, `command_line`) populated for execution artifacts.
- Network tuples (`source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`) populated for traffic artifacts.
- No contract mismatches detected.
