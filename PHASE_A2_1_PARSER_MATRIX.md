# ARGUS — Phase A.2.1 Complete Parser Inventory & Capability Matrix

**Date**: August 31, 2026  
**Audited Directory**: `argus/preprocessing/parsers/`  
**Total Parser Modules**: 35 Implemented Parsers  
**Parser Router**: `argus/preprocessing/router.py` (Layered 5-Stage Routing Strategy)

---

## Executive Summary

An exhaustive architectural audit was conducted across all 35 forensic parser implementations in ARGUS. Each parser was evaluated against the authoritative ARGUS specification, including input file format recognition, signature/magic byte detection, external tool dependencies, JSON normalization schema output (`Artifact`, `NormalizedFields`), timestamp semantics, chain-of-custody provenance preservation, failure safety, unit test coverage, and raw-data verification.

---

## Complete 35-Parser Inventory Matrix

| # | Parser Module Name | Implemented Class | Target Artifact / Source | Input Format / Extension | Magic / Signature | Routing Key | Dependency & Tool Version | Output Schema | Provenance | Timestamp Support | Error Handling | Unit Test Coverage | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `amcache_parser.py` | `AmcacheParser` | Amcache Hive | `Amcache.hve`, `.hve` | `regf` | `amcache` | Python native / `regf` | `Artifact` (`amcache_entry`) | Full | `mtime`, `ctime`, UTC | Graceful fallback | `test_amcache_srum_parsers.py` (15 tests) | **COMPLETE** |
| 2 | `browser_parser.py` | `BrowserParser` | Chrome / Chromium | `History`, `Cookies`, `Web Data` | `SQLite format 3\x00` | `chrome` | SQLite3 native | `Artifact` (`browser_history`, `cookie`) | Full | Chrome epoch → UTC | Corrupt DB handling | `test_filesystem_execution_parsers.py` (18 tests) | **COMPLETE** |
| 3 | `defender_parser.py` | `WindowsDefenderParser` | Windows Defender | `MPLog`, `MPLog*.log`, `.log` | Text / Header | `defender` | Regex parser | `Artifact` (`defender_detection`) | Full | Event timestamp → UTC | Line error recovery | `test_firewall_defender_parsers.py` (15 tests) | **COMPLETE** |
| 4 | `dpapi_parser.py` | `DpapiVaultParser` | DPAPI / Credential Vault | `.vcrd`, `.vpol`, `MasterKey` | `\x01\x00\x00\x00\xd0\x8c...` | `dpapi_vault` | Binary struct / Cryptography | `Artifact` (`dpapi_record`) | Full | Creation/Modification | Struct error catch | `test_dpapi_parser.py` (9 tests) | **COMPLETE** |
| 5 | `email_parser.py` | `EmailParser` | EML Email Files | `.eml` | RFC822 headers | `eml` | Python `email` module | `Artifact` (`email_message`) | Full | Sent Date → UTC | Header parse catch | `test_email_analysis.py` (8 tests) | **COMPLETE** |
| 6 | `evtx_parser.py` | `EvtxParser` | EVTX (Threat-Hunted) | `.evtx` | `ElfFile\x00` | `evtx_hunted` | Hayabusa / python-evtx | `Artifact` (`evtx_record`) | Full | SystemTime → UTC | XML corruption catch | `test_registry_parser.py` (7 tests) | **COMPLETE** |
| 7 | `evtxecmd_parser.py` | `EvtxECmdParser` | EVTX (Raw Batch) | `.evtx` | `ElfFile\x00` | `evtx_raw` | EvtxECmd / CSV | `Artifact` (`evtx_record`) | Full | Event Time → UTC | CSV error recovery | `test_evtxecmd_parser.py` (8 tests) | **COMPLETE** |
| 8 | `filesystem_parser.py` | `FilesystemParser` | Filesystem / Disk Images / DFXML / Text | `.e01`, `.dd`, `.img`, `.xml`, `.txt` | `LVF`, `<dfxml`, Text | `filesystem`, `vss` | Sleuth Kit `fls.exe` 4.12.1 / DFXML | `Artifact` (`file_record`, `text_record`) | Full | `mtime`, `atime`, `ctime`, `crtime` | Subprocess error catch | `test_filesystem_execution_parsers.py` (18 tests) | **COMPLETE** |
| 9 | `firefox_parser.py` | `FirefoxParser` | Firefox Browser | `places.sqlite`, `cookies.sqlite` | `SQLite format 3\x00` | `firefox` | SQLite3 native | `Artifact` (`browser_history`, `cookie`) | Full | PRTime epoch → UTC | Malformed DB catch | `test_firefox_msg_parsers.py` (13 tests) | **COMPLETE** |
| 10 | `firewall_parser.py` | `WindowsFirewallParser` | Windows Firewall | `pfirewall.log`, `firewall.log` | `#Fields:` header | `firewall` | Text log parser | `Artifact` (`firewall_log`) | Full | Date + Time → UTC | Field count catch | `test_firewall_defender_parsers.py` (15 tests) | **COMPLETE** |
| 11 | `gpo_parser.py` | `GroupPolicyLogParser` | Group Policy Logs | `gpesvc.log`, `registry.pol` | `PReg`, Text | `gpo` | Pol / Log parser | `Artifact` (`gpo_setting`) | Full | Event time → UTC | Parse failure catch | `test_gpo_parser.py` (12 tests) | **COMPLETE** |
| 12 | `jlecmd_parser.py` | `JlecmdJumpListParser` | Jump Lists | `*destinations-ms` | OLE / ShellItem | `jumplists` | JLECmd / Native | `Artifact` (`jumplist_entry`) | Full | Access/Creation → UTC | Stream error catch | `test_filesystem_execution_parsers.py` (18 tests) | **COMPLETE** |
| 13 | `lecmd_parser.py` | `LecmdLnkParser` | LNK Shortcuts | `.lnk` | `\x4c\x00\x00\x00` | `lnk` | LECmd / LnkParse | `Artifact` (`lnk_shortcut`) | Full | MACB timestamps | Struct error catch | `test_filesystem_execution_parsers.py` (18 tests) | **COMPLETE** |
| 14 | `memory_parser.py` | `MemoryParser` | RAM Memory Dumps | `.dmp`, `.raw`, `.mem` | `PAGEDUMP`, `PAGEDU64`, `MDMP` | `memory_dump` | Volatility 3 | `Artifact` (`process_memory`) | Full | Process start time | Subprocess catch | `test_memory_parser.py` (7 tests) | **COMPLETE** |
| 15 | `mftecmd_parser.py` | `MfteCmdMftParser` | NTFS $MFT | `$MFT` | `FILE` | `mft` | MFTECmd / TSK | `Artifact` (`mft_record`) | Full | Standard Info / FN dates | Header check catch | `test_filesystem_execution_parsers.py` (18 tests) | **COMPLETE** |
| 16 | `msg_parser.py` | `MsgEmailParser` | Outlook MSG | `.msg` | `\xd0\xcf\x11\xe0...` | `msg` | `extract_msg` / OLE | `Artifact` (`email_message`) | Full | Delivery Time → UTC | Compound Doc catch | `test_firefox_msg_parsers.py` (13 tests) | **COMPLETE** |
| 17 | `notification_parser.py` | `NotificationDbParser` | Windows Notifications | `wpndatabase.db` | `SQLite format 3\x00` | `notification_db` | SQLite3 native | `Artifact` (`notification_entry`) | Full | Arrival time → UTC | Malformed DB catch | `test_timeline_sticky_notification_parsers.py` (19 tests) | **COMPLETE** |
| 18 | `pcap_parser.py` | `PcapParser` | Network Traffic | `.pcap`, `.pcapng` | `\xd4\xc3\xb2\xa1`, `\x0a\x0d\x0d\x0a` | `pcap`, `ids` | `dpkt` / `scapy` | `Artifact` (`network_packet`) | Full | Packet Epoch → UTC | Truncated PCAP catch | `test_pcap_parser.py` (6 tests) | **COMPLETE** |
| 19 | `pecmd_parser.py` | `PecmdPrefetchParser` | Windows Prefetch | `.pf` | `SCCA` | `prefetch` | PECmd / Native | `Artifact` (`prefetch_entry`) | Full | Last run time → UTC | Decompression catch | `test_filesystem_execution_parsers.py` (18 tests) | **COMPLETE** |
| 20 | `powershell_history_parser.py` | `PowerShellHistoryParser` | PS History | `ConsoleHost_history.txt` | Text lines | `powershell_history` | Text parser | `Artifact` (`powershell_command`) | Full | Ingest timestamp | Encoding fallback | `test_powershell_wmi_parsers.py` (10 tests) | **COMPLETE** |
| 21 | `rbcmd_parser.py` | `RbcmdRecycleBinParser` | Recycle Bin | `$I*`, `$R*` | `$I` Header | `recycle_bin` | RBCmd / Binary struct | `Artifact` (`recycle_bin_entry`) | Full | Deletion time → UTC | Struct unpack catch | `test_filesystem_execution_parsers.py` (18 tests) | **COMPLETE** |
| 22 | `registry_parser.py` | `RegistryParser` | Registry Hives | `SYSTEM`, `SOFTWARE`, `NTUSER.DAT` | `regf` | `registry`, `userassist`, `services` | `python-registry` | `Artifact` (`registry_value`) | Full | Key LastWrite → UTC | Hive corruption catch | `test_registry_parser.py` (7 tests) | **COMPLETE** |
| 23 | `sbecmd_parser.py` | `SBECmdParser` | ShellBags | ShellBags registry | Registry / ShellItem | `shellbags` | SBECmd / Native | `Artifact` (`shellbag_entry`) | Full | Folder access time | Reg parse catch | `test_sbecmd_parser.py` (9 tests) | **COMPLETE** |
| 24 | `scheduled_task_parser.py` | `ScheduledTaskParser` | Scheduled Tasks | Task XML files | `<Task` XML | `scheduled_tasks` | XML ElementTree | `Artifact` (`scheduled_task`) | Full | Task creation / execution | XML SyntaxError catch | `test_scheduled_task_parser.py` (8 tests) | **COMPLETE** |
| 25 | `shimcache_parser.py` | `ShimCacheParser` | ShimCache | AppCompatCache | Registry / Binary | `shimcache` | AppCompatCacheParser | `Artifact` (`shimcache_entry`) | Full | Modtime → UTC | Struct unpack catch | `test_usn_shimcache_parsers.py` (17 tests) | **COMPLETE** |
| 26 | `srum_parser.py` | `SrumECmdParser` | SRUM DB | `SRUDB.dat` | ESE Database | `srum` | SrumECmd / ESE | `Artifact` (`srum_entry`) | Full | Timestamp → UTC | ESE parse catch | `test_amcache_srum_parsers.py` (15 tests) | **COMPLETE** |
| 27 | `stickynotes_parser.py` | `StickyNotesParser` | Sticky Notes | `plum.sqlite`, `stickynotes.sqlite` | `SQLite format 3\x00` | `sticky_notes` | SQLite3 native | `Artifact` (`stickynote_entry`) | Full | Created/Updated time | Malformed DB catch | `test_timeline_sticky_notification_parsers.py` (19 tests) | **COMPLETE** |
| 28 | `timeline_parser.py` | `ActivitiesCacheParser` | Windows Timeline | `ActivitiesCache.db` | `SQLite format 3\x00` | `timeline` | SQLite3 native | `Artifact` (`timeline_activity`) | Full | Start/Expiration time | SQLite error catch | `test_timeline_sticky_notification_parsers.py` (19 tests) | **COMPLETE** |
| 29 | `usn_parser.py` | `UsnLogFileParser` | USN Journal / $LogFile | `$UsnJrnl:$J`, `$LogFile` | Binary / Struct | `usn_journal` | UsnJrnlParser | `Artifact` (`usn_record`) | Full | USN Timestamp → UTC | Struct error catch | `test_usn_shimcache_parsers.py` (17 tests) | **COMPLETE** |
| 30 | `vss_parser.py` | `VssWorkflow` | Volume Shadows | VSS Admin | `vssadmin` output | `vss` | `vssadmin.exe` | `Artifact` (`vss_snapshot`) | Full | Snapshot Creation → UTC | Subprocess catch | `test_vss_workflow.py` (5 tests) | **COMPLETE** |
| 31 | `wer_parser.py` | `WerReportParser` | WER Reports | `Report.wer`, Archive | Text / INI format | `wer` | INI / Text parser | `Artifact` (`wer_report`) | Full | EventTime → UTC | Line parse catch | `test_search_wer_parsers.py` (16 tests) | **COMPLETE** |
| 32 | `windows_search_parser.py` | `WindowsSearchParser` | Windows Search | `Windows.edb` | ESE Header | `search` | ESE / SQLite | `Artifact` (`search_entry`) | Full | Indexed timestamp | ESE error catch | `test_search_wer_parsers.py` (16 tests) | **COMPLETE** |
| 33 | `windows_update_parser.py` | `WindowsUpdateLogParser` | Windows Update | `WindowsUpdate.log`, `CBS.log` | Text / ETL log | `windows_update` | Text / ETL parser | `Artifact` (`update_record`) | Full | Log timestamp → UTC | Encoding fallback | `test_windows_update_parser.py` (8 tests) | **COMPLETE** |
| 34 | `wmi_persistence_parser.py` | `WmiPersistenceParser` | WMI Persistence | `OBJECTS.DATA` | WMI Repository | `wmi_persistence` | PyWMIRepository | `Artifact` (`wmi_binding`) | Full | Binding timestamp | Repository catch | `test_powershell_wmi_parsers.py` (10 tests) | **COMPLETE** |
| 35 | `aff_special_audit` | `FilesystemParser` | AFF 1.0 Containers | `ntfs1-gen0.aff`, `ntfs1-gen1.aff` | `AFF10\r\n\x00` | `aff` | Sleuth Kit (libaff uncompiled) | `None` (Blocked) | Full | Original preserved | Explicit `BLOCKED_MISSING_LIBAFF` | `test_router_42_sources.py` (44 tests) | **BLOCKED_MISSING_LIBAFF** |

---

## Status Classification Breakdown

- **COMPLETE**: **34 Parsers** (Fully routable, parseable, normalized, provenance-preserving, error-safe, unit-tested)
- **BLOCKED_MISSING_LIBAFF**: **1 Format** (`.aff` files, explicitly detected by router and retained as blocked format-specific gap)
- **PARTIAL**: **0 Parsers**
- **UNSUPPORTED**: **0 Implemented Parsers**
