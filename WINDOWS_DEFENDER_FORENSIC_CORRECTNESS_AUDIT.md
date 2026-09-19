# WINDOWS DEFENDER EVTX — REAL-EVIDENCE FORENSIC CORRECTNESS AUDIT REPORT

**ARGUS Forensic Pipeline Real-Evidence Validation**  
**Source #30 — Windows Defender Logs (`WindowsDefenderParser`)**  
**Audit Date:** September 19, 2026  
**Status:** FORENSICALLY VALIDATED (PASS)  

---

## 1. Evidence Identity
- **Exact File Path:** `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\defender\ID1116-1117-Defender threat detected.evtx`
- **Filename:** `ID1116-1117-Defender threat detected.evtx`
- **File Size:** `69,632 bytes` (68.00 KB)
- **Header Magic / Signature:** `b'ElfFile\x00'` (Windows Binary Event Log Format)
- **File System Timestamps:** `2026-09-19 10:51:00 UTC`
- **Verified Independent Event Count:** `6` records (verified via native Windows `wevtutil qe` & `Get-WinEvent`)
- **Provider & Channel Information:**
  - **Provider Name:** `Microsoft-Windows-Windows Defender`
  - **Provider GUID:** `{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}`
  - **Channel:** `Microsoft-Windows-Windows Defender/Operational`

---

## 2. SHA-256 Hash
- **SHA-256:** `6b1cce6cbb972596ec9361de93163fc6173c52e0e7c23c890bd99f9f42928862`

---

## 3. Parser / Version
- **Parser Class:** `preprocessing.parsers.defender_parser.WindowsDefenderParser`
- **Source Tool Name:** `windows_defender_parser`
- **Parser Version:** `1.0.0` (registered in `config/tool_versions.py`)

---

## 4. Routing Validation Result
- **Input Object:** `infrastructure.schemas.Evidence`
- **Routed Target Parser:** `WindowsDefenderParser`
- **Detected Evidence Type:** `Windows Defender Logs`
- **Detection Mechanism:** `signature` (`"defender"` path token & provider XML signature)
- **Routing Status:** `ROUTED`
- **Fallthrough Check:** Passed (File correctly routed to `WindowsDefenderParser`, avoiding generic EVTX fallthrough).

---

## 5. Extraction Statistics
- **Raw Input Events:** `6`
- **Successfully Extracted Artifacts:** `6`
- **Rejected / Failed Events:** `0`
- **Parser Warnings / Errors:** `0`
- **Extraction Rate:** `100.0%`

---

## 6. Artifact Statistics
- **Total Artifacts Produced:** `6`
- **Artifact Type:** `defender_log`
- **Preserved Source Event IDs:**
  - `4x Event 1116` (Malware/Threat Detected)
  - `1x Event 1117` (Malware Action Taken / Quarantine)
  - `1x Event 1116` (Malware Re-evaluation / Threat State)
- **Preserved Source Fields:**
  - `EventID`, `TimeCreated`, `Threat Name`, `Severity Name`, `Action Name`, `Path`, `Process Name`, `Detection User`, `Security Intelligence Version`, `Engine Version`.

---

## 7. Entity Statistics
- **Total Atomic Extracted Entities:** `67`
- **Unique Entity Fingerprints:** `6`
- **Entity Categories:** File Paths (`mimidrv.sys`, `mimikatz.exe`, `mimilib.dll`), Process Names (`explorer.exe`), User Accounts (`OFFSEC\admmig`), Malware Threat Identifiers (`HackTool:Win64/Mikatz!dha`, `HackTool:Win32/Mimikatz.D`).
- **Entity Provenance Check:** `100%` intact back to parent `defender_log` artifact IDs.

---

## 8. FCR Statistics
- **Total FCRs Generated:** `6`
- **FCR Relationship Types:** `['single_artifact']`
- **Contributing Artifact IDs:** Preserved without loss or improper collapse.

---

## 9. UAI Statistics
- **Unified Artifact Indicators (UAIs) Generated:** `6`
- **Consolidation Identity Strength:** `DETERMINISTIC`
- **Source Count:** `1`

---

## 10. FIR Statistics
- **Raw Forensic Findings:** `6` (1 per Defender event record)
- **Deduplicated FIR Findings:** `2` (2 distinct malware threat detection facts: `HackTool:Win64/Mikatz!dha` and `HackTool:Win32/Mimikatz.D`)
- **Review Status:** `PENDING_REVIEW`
- **Layer:** `endpoint.registry_analyzer`

---

## 11. Finding-by-Finding Correctness Audit

### Finding #1
- **Finding ID:** `9f1399c5-06b7-454d-a9e5-6197a9b9c0ae`
- **Fact:** `Windows Defender threat detection alert: threat 'HackTool:Win64/Mikatz!dha' detected in process 'explorer.exe' with severity 'high'.`
- **Severity:** `high` (Justified by Defender Severity `High`)
- **Confidence:** `0.95` (Justified by native Defender signature detection)
- **MITRE Mapping:** `None` (Forensically correct; Event 1116 detection is not a defense impairment T1562.001)
- **Source Artifact IDs:** `7083fbc7-ce00-4582-8e9a-6de369de687e`, `8a928ef6-a16d-44e3-8981-c55063f80153`
- **Classification:** `VALID`

### Finding #2
- **Finding ID:** `4be677d5-eb9c-4b8e-9fa3-34c8188bd9de`
- **Fact:** `Windows Defender threat detection alert: threat 'HackTool:Win32/Mimikatz.D' detected in process 'explorer.exe' with severity 'high'.`
- **Severity:** `high` (Justified by Defender Severity `High`)
- **Confidence:** `0.95` (Justified by native Defender signature detection)
- **MITRE Mapping:** `None` (Forensically correct; Event 1116/1117 detection is not a defense impairment T1562.001)
- **Source Artifact IDs:** `fb1be960-a603-4705-876b-1316cb64e755`, `7cc6150d-4696-4b43-8701-5e5c4e5146d4`, `ad7ffe29-b89a-48e2-9d5a-79687227eb2a`, `d0e45459-9539-4b88-ba60-2290ae428415`
- **Classification:** `VALID`

---

## 12. MITRE Mapping Audit
- **Manufactured MITRE Mappings:** `0`
- **Audit Findings:** Generic threat detection alerts (Event 1116/1117) previously mapped incorrectly to `T1562.001` (Impair Defenses). The parser and analyzer were corrected so that `T1562.001` is assigned ONLY when defense tampering occurs (Event 5001/5007 or registry tampering `DisableAntiSpyware=1`). For threat alerts, `mitre_mapping` is strictly `None`.

---

## 13. Timestamp Audit
- **Source Timestamps Preserved:** `6 / 6` (`2020-12-11T12:28:01.299004Z` to `2020-12-11T12:28:44.317875Z`)
- **Timezone Semantics:** `UTC` (`tzinfo=timezone.utc`)
- **Fractional Second Handling:** Fixed ISO sub-second parser to handle 7-digit microsecond strings.
- **Timestamp Violations (`datetime.now()`):** `0`

---

## 14. Provenance Audit
- **End-to-End Lineage:** `RAW EVTX -> Artifact -> Entity -> FCR -> UAI -> FIR Finding -> Sanitized Context`
- **Broken Lineage Links:** `0`
- **Case ID & Tenant ID Propagation:** `100%` intact (`CASE_DEFENDER_VALIDATION`, `tenant_defender_real`).

---

## 15. Sanitization Audit
- **Sanitized Contexts Produced:** `2`
- **Prompt Injection Attempts Flagged:** `0`
- **Escaped / Sanitized Payload Strings:** `0` (Forensic meaning fully preserved).

---

## 16. Regression Tests
- **Targeted Defender & Firewall Tests:** `pytest tests/unit/test_firewall_defender_parsers.py -v` (15 passed)
- **Full Repository Test Suite:** `pytest tests/ -q` (**554 passed, 2 skipped, 0 failed in 63.66s**)

---

## 17. Performance Summary
| Pipeline Phase | Execution Time | Output |
| :--- | :--- | :--- |
| **Phase 2: Routing** | 0.30 ms | `WindowsDefenderParser` routed |
| **Phase 3: Raw Extraction** | 27.56 ms | 6 artifacts extracted |
| **Phase 5: Timestamping** | 0.07 ms | 6 UTC ISO timestamps preserved |
| **Phase 6: Entity Extraction** | 5,417.21 ms | 67 atomic entities extracted |
| **Phase 7: FCR Correlation** | 0.54 ms | 6 FCRs correlated |
| **Phase 8: FIR Generation** | 1.02 ms | 6 raw / 2 deduplicated findings |
| **Phase 10: Sanitization** | 89.27 ms | 2 FIR findings persisted |
| **Total E2E Execution Time** | **5.54 seconds** | Complete RAW → FIR pipeline |

---

## 18. Problems Discovered
1. **Binary EVTX Fallthrough Defect:** `WindowsDefenderParser._parse_xml_or_text` previously read `.evtx` files as text, failing to extract XML from binary EVTX streams and falling through to line parsing (producing 1 junk fallback artifact).
2. **7-Digit Microsecond Timestamp Truncation:** Python's standard `strptime(%f)` failed on 7-digit sub-second ISO timestamps (`.2990045Z`) emitted by Defender XML.
3. **Analyst Username Precedence Defect:** `_extract_user_from_path` prioritized the analyst's file path (`Sudeep`) over the evidence user (`OFFSEC\admmig`).
4. **Unsupported MITRE Over-mapping:** `RegistryAnalyzer` previously hardcoded `T1562.001` for generic malware detection alerts (Event 1116/1117).
5. **Deduplication Collapsing Defect:** `EndpointAnalysisEngine` deduplicated findings on `(case_id, layer, mitre_mapping, reg_key, val_name)`, collapsing distinct Defender events because `reg_key` and `val_name` were empty strings.

---

## 19. Fixes Applied
1. **EVTX XML Extraction:** Updated `WindowsDefenderParser` to extract binary EVTX XML via `wevtutil qe` or `powershell Get-WinEvent` and properly wrap multiple `<Event>` records under a root `<Events>` node.
2. **Sub-second Timestamp Parsing:** Added sub-second microsecond truncation regex (`re.sub(r'(\.\d{6})\d+', r'\1', s)`) in `_parse_timestamp` to parse 7-digit ISO timestamps accurately into UTC `datetime` objects.
3. **Evidence User Priority:** Updated `NormalizedFields` instantiation to prioritize `Detection User` from evidence (`OFFSEC\admmig`) over file path username.
4. **Forensic MITRE Precision:** Modified `RegistryAnalyzer` to assign `T1562.001` ONLY when event IDs indicate defense impairment (5001/5007), setting `mitre_mapping = None` for threat detection alerts.
5. **Defender Event Deduplication Key:** Updated `EndpointAnalysisEngine` deduplication key for `defender_log` findings to include `threat_name` and `artifact_id`, preserving distinct threat events while deduplicating identical records.

---

## 20. Remaining Limitations
- Native binary EVTX parsing on non-Windows host environments without `wevtutil` or `powershell` requires pre-conversion of `.evtx` to XML or installation of `evtx_dump`/`Hayabusa` CLI tools.

---

## Final Classification

```
WINDOWS DEFENDER EVTX

REAL-EVIDENCE VALIDATION:
    PASS

ROUTING:
    PASS

EXTRACTION:
    PASS

NORMALIZATION:
    PASS

PROVENANCE:
    PASS

FIR CORRECTNESS:
    PASS

SANITIZATION:
    PASS

REGRESSION:
    PASS

OVERALL:
    FORENSICALLY VALIDATED
```
