# ARGUS — Phase A.2.2 Artifact Extraction Matrix

**Date**: August 31, 2026  
**Module**: `preprocessing/artifact_extractor/extractor.py` (`ArtifactExtractor`)  
**Downstream Target**: `preprocessing/fcr_engine/` (`FCREngine`)

---

## 1. Supported Forensic Artifact Categories & Extraction Mapping Matrix

| Category ID | Artifact Category | Input Artifact Types | Extracted Entity Types | Field Extraction Strategy | Output Target | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FILESYSTEM** | File System & Disk Timelines | `file_record`, `mft_record`, `usn_record`, `lnk_shortcut`, `jumplist_entry`, `prefetch_entry`, `recycle_bin_entry`, `shimcache_entry`, `vss_snapshot` | `file_path`, `file_name`, `hash`, `mtime`, `atime`, `ctime`, `deleted` | ioc-finder + regex + path resolution | `FCREngine` | **COMPLETE** |
| **PROCESS / EXECUTION** | Process & Command Line Execution | `process_event`, `process_memory`, `powershell_command` | `process_id`, `parent_process_id`, `process_name`, `process_command_line`, `user`, `host` | Span resolver + CyNER NER | `FCREngine` | **COMPLETE** |
| **REGISTRY / PERSISTENCE** | Registry & Persistence | `registry_value`, `amcache_entry`, `scheduled_task`, `wmi_binding`, `gpo_setting`, `dpapi_record` | `registry_key`, `registry_value`, `registry_value_data`, `rule_name`, `severity` | System Object Registry + ioc-finder | `FCREngine` | **COMPLETE** |
| **NETWORK** | Network Traffic & Telemetry | `network_packet`, `network_connection`, `dns_query`, `http_request`, `tls_session`, `firewall_log` | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `domain`, `url`, `ip_scope` | TLD extract + IP validator | `FCREngine` | **COMPLETE** |
| **MEMORY** | Memory Analysis | `memory.pslist`, `memory.psscan`, `memory.pstree`, `memory.dlllist`, `memory.ldrmodules`, `memory.netscan`, `memory.netstat`, `memory.malfind`, `memory.vadinfo`, `memory.lsass`, `memory.timeline` | `process_id`, `process_name`, `src_ip`, `dst_ip`, `src_port`, `dst_port` | Volatility memory plugin resolution | `FCREngine` | **COMPLETE** |
| **EMAIL** | Email & Messaging | `email_message`, `email.header`, `email.body` | `sender`, `recipients`, `subject`, `attachment_hash`, `url`, `domain` | RFC822 parser + ioc-finder | `FCREngine` | **COMPLETE** |
| **BROWSER / USER ACTIVITY** | User Activity & Web Artifacts | `browser_history`, `cookie`, `shellbag_entry`, `timeline_activity`, `search_entry`, `stickynote_entry`, `notification_entry`, `srum_entry`, `wer_report` | `url`, `domain`, `user`, `host`, `first_connected`, `last_connected`, `friendly_name` | Hindsight + SQLite entity resolver | `FCREngine` | **COMPLETE** |
| **DEFENDER / DETECTION** | Security Alerts & Logs | `defender_detection`, `evtx_record`, `gpo_event`, `threat_detection`, `hayabusa_alert` | `rule_name`, `severity`, `threat_actor`, `malware` | YaraScanner + CyNER NER | `FCREngine` | **COMPLETE** |

---

## 2. Category Coverage Summary

- **Total Taxonomy Categories**: **8 Forensic Categories**
- **Total Handled Input Artifact Types**: **55 Input Types**
- **Deduplication Strategy**: Provenance-based identity key (`case_id` + `evidence_id` + `source_artifact_id` + `artifact_type` + `canonical_hash`)
- **FCR Compatibility**: **100% Compatible** (`FCREngine.correlate()`)
