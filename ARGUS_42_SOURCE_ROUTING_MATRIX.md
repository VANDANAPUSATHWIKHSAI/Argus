# ARGUS 42-Source Routing & Integration Status Matrix

This document provides the authoritative, machine-readable routing and integration status for all 42 evidence sources declared in the ARGUS matrix.

| # | Source Name | Registered | Routable | Detection Method | Parser Implementation | Output Schema | FCR? | Tested? | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Memory Dump | Yes | Yes | Signature / Ext (`PAGEDUMP`, `MDMP`, `.dmp`, `.raw`) | `MemoryParser` | `process`, `network`, `dll`, `rootkit` | Yes | Yes | `PREVIOUSLY_REAL_EVIDENCE_VALIDATED` | Verified against 388 memory findings baseline. |
| 2 | PCAP / Network Traffic | Yes | Yes | Signature (`\xd4\xc3\xb2\xa1`, `.pcap`) | `PcapParser` | `dns_query`, `http_request`, `tls_session` | Yes | Yes | `PREVIOUSLY_REAL_EVIDENCE_VALIDATED` | Verified against PCAP real-evidence baseline. |
| 3 | Network Security / IDS | Yes | Yes | Explicit Metadata / Ext | `PcapParser` | `ids_alert`, `network_connection` | Yes | Yes | `IMPLEMENTED_NOT_VALIDATED` | Integrates Suricata / Zeek telemetry into FCR. |
| 4 | Windows Event Logs (EVTX) — raw | Yes | Yes | Signature / Metadata (`stream=raw`) | `EvtxECmdParser` | `evtx_record` | Yes | Yes | `PREVIOUSLY_REAL_EVIDENCE_VALIDATED` | Raw EvtxECmd CSV output conversion. |
| 5 | Windows Event Logs (EVTX) — threat-hunted | Yes | Yes | Signature (`ElfFile\x00`) / Ext (`.evtx`) | `EvtxParser` | `evtx_record`, `threat_finding` | Yes | Yes | `PREVIOUSLY_REAL_EVIDENCE_VALIDATED` | Threat-hunted EVTX via Hayabusa. |
| 6 | Windows Registry | Yes | Yes | Signature (`regf`) / Filename (`NTUSER.DAT`) | `RegistryParser` | `registry_key`, `registry_value` | Yes | Yes | `PREVIOUSLY_REAL_EVIDENCE_VALIDATED` | Verified against Registry real-evidence baseline. |
| 7 | Browser Artifacts — Chrome / Chromium | Yes | Yes | Signature (SQLite) / Path (`Chrome`) | `BrowserParser` | `browser_history`, `download`, `cookie` | Yes | Yes | `PREVIOUSLY_REAL_EVIDENCE_VALIDATED` | Verified against Chrome real-evidence baseline. |
| 8 | Browser Artifacts — Firefox | Yes | Yes | Signature (SQLite) / Path (`Firefox`) | `FirefoxParser` | `firefox_history`, `firefox_download` | Yes | Yes | `COMPLETE` | Unit & integration tested. |
| 9 | Email — .eml | Yes | Yes | Signature (`From:`) / Ext (`.eml`) | `EmailParser` | `email_message`, `attachment` | Yes | Yes | `COMPLETE` | RFC822 parser with header sanitization. |
| 10 | Email — .msg / Outlook | Yes | Yes | Signature (OLE `\xd0\xcf\x11\xe0`) / Ext (`.msg`) | `MsgEmailParser` | `msg_message`, `attachment` | Yes | Yes | `COMPLETE` | OLE Compound Document parser. |
| 11 | MFT / NTFS | Yes | Yes | Filename (`$MFT`) | `MfteCmdMftParser` | `mft_record` | Yes | Yes | `COMPLETE` | Wraps MFTECmd parser output. |
| 12 | Prefetch | Yes | Yes | Signature (`SCCA`) / Ext (`.pf`) | `PecmdPrefetchParser` | `prefetch_entry` | Yes | Yes | `COMPLETE` | PECmd execution artifact parser. |
| 13 | LNK Files | Yes | Yes | Ext (`.lnk`) | `LecmdLnkParser` | `lnk_file` | Yes | Yes | `COMPLETE` | LECmd shortcut parser. |
| 14 | Jump Lists | Yes | Yes | Filename (`AutomaticDestinations`) | `JlecmdJumpListParser` | `jumplist_entry` | Yes | Yes | `COMPLETE` | JLECmd jump list parser. |
| 15 | Recycle Bin | Yes | Yes | Path / Filename (`$I*`, `$R*`) | `RbcmdRecycleBinParser` | `recycle_bin_item` | Yes | Yes | `COMPLETE` | RBCmd deleted file artifact parser. |
| 16 | Amcache | Yes | Yes | Signature (`regf`) / Filename (`Amcache.hve`) | `AmcacheParser` | `amcache_entry` | Yes | Yes | `COMPLETE` | AmcacheParser execution history. |
| 17 | SRUM | Yes | Yes | Filename (`SRUDB.dat`) | `SrumECmdParser` | `srum_entry` | Yes | Yes | `COMPLETE` | System Resource Usage Monitor parser. |
| 18 | File System / Disk Image | Yes | Yes | Ext (`.dd`, `.img`, `.e01`, `.iso`) | `FilesystemParser` | `filesystem_entry` | Yes | Yes | `COMPLETE` | SleuthKit / fls filesystem container parser. |
| 19 | USN Journal / $LogFile | Yes | Yes | Filename (`$UsnJrnl`, `$LogFile`) | `UsnLogFileParser` | `usn_record` | Yes | Yes | `COMPLETE` | NTFS change journal parser. |
| 20 | ShimCache / AppCompatCache | Yes | Yes | Path / Filename (`appcompatcache.bin`) | `ShimCacheParser` | `shimcache_entry` | Yes | Yes | `COMPLETE` | AppCompatCache binary parser. |
| 21 | Scheduled Tasks | Yes | Yes | Signature (`<Task`) / Path (`Tasks`) | `ScheduledTaskParser` | `scheduled_task` | Yes | Yes | `COMPLETE` | XML Scheduled Task parser. |
| 22 | PowerShell Command History | Yes | Yes | Filename (`ConsoleHost_history.txt`) | `PowerShellHistoryParser` | `powershell_history` | Yes | Yes | `COMPLETE` | Command history parser with timestamp preservation. |
| 23 | UserAssist | Yes | Yes | Path / Hive (`NTUSER.DAT`) | `RegistryParser` | `registry_key` | Yes | Yes | `COMPLETE` | Registry UserAssist key parser. |
| 24 | RecentDocs | Yes | Yes | Path / Hive (`NTUSER.DAT`) | `RegistryParser` | `registry_key` | Yes | Yes | `COMPLETE` | Registry RecentDocs key parser. |
| 25 | ShellBags | Yes | Yes | Path (`ShellBags`) | `SBECmdParser` | `shellbag_entry` | Yes | Yes | `COMPLETE` | SBECmd folder interaction parser. |
| 26 | BAM / DAM | Yes | Yes | Path / Hive (`SYSTEM`) | `RegistryParser` | `registry_key` | Yes | Yes | `COMPLETE` | Background Activity Moderator parser. |
| 27 | MUICache | Yes | Yes | Path / Hive (`UsrClass.dat`) | `RegistryParser` | `registry_key` | Yes | Yes | `COMPLETE` | Multilingual User Interface cache. |
| 28 | Services | Yes | Yes | Path / Hive (`SYSTEM`) | `RegistryParser` | `registry_key` | Yes | Yes | `COMPLETE` | Windows System Services parser. |
| 29 | WMI Persistence | Yes | Yes | Filename (`OBJECTS.DATA`) / Path (`\subscription`) | `WmiPersistenceParser` | `wmi_event_consumer` | Yes | Yes | `COMPLETE` | WMI repository persistence parser. |
| 30 | Windows Defender Logs | Yes | Yes | Path (`Defender`) / Signature EVTX | `WindowsDefenderParser` | `defender_alert` | Yes | Yes | `COMPLETE` | Windows Defender log parser. |
| 31 | Windows Firewall Logs | Yes | Yes | Path (`pfirewall.log`) | `WindowsFirewallParser` | `firewall_log` | Yes | Yes | `COMPLETE` | Windows Firewall W3C log parser with flow retention. |
| 32 | Windows Timeline / ActivitiesCache | Yes | Yes | Signature (SQLite) / Filename (`ActivitiesCache.db`) | `ActivitiesCacheParser` | `activity_cache` | Yes | Yes | `COMPLETE` | Windows 10/11 ActivitiesCache parser. |
| 33 | Windows Search History | Yes | Yes | Signature (ESE) / Filename (`Windows.edb`) | `WindowsSearchParser` | `search_index_entry` | Yes | Yes | `COMPLETE` | Windows EDB search index parser. |
| 34 | Network Configuration | Yes | Yes | Path / Hive (`SYSTEM`) | `RegistryParser` | `registry_key` | Yes | Yes | `COMPLETE` | Registry network configuration parser. |
| 35 | Windows Sticky Notes | Yes | Yes | Signature (SQLite) / Filename (`plum.sqlite`) | `StickyNotesParser` | `sticky_note` | Yes | Yes | `COMPLETE` | Windows Sticky Notes parser. |
| 36 | Windows Notification Database | Yes | Yes | Signature (SQLite) / Filename (`wpndatabase.db`) | `NotificationDbParser` | `notification_entry` | Yes | Yes | `COMPLETE` | Windows Action Center notification DB. |
| 37 | WER Reports | Yes | Yes | Ext (`.wer`) / Filename (`Report.wer`) | `WerReportParser` | `wer_report` | Yes | Yes | `COMPLETE` | Windows Error Reporting parser. |
| 38 | Windows Update / Patch History | Yes | Yes | Filename (`WindowsUpdate.log`, `CBS.log`) | `WindowsUpdateLogParser` | `windows_update_log` | Yes | Yes | `COMPLETE` | Windows Update / CBS log parser. |
| 39 | Group Policy Application Logs | Yes | Yes | Signature (`PReg`) / Ext (`.pol`, `.log`) | `GroupPolicyLogParser` | `gpo_log` | Yes | Yes | `COMPLETE` | Group Policy log and registry.pol parser. |
| 40 | Sysmon Operational Logs | Yes | Yes | Signature EVTX / Filename (`Sysmon%4Operational`) | `EvtxParser` | `evtx_record` | Yes | Yes | `COMPLETE` | Deterministic Sysmon EVTX routing. |
| 41 | Volume Shadow Copies (VSS) | Yes | Yes | Explicit Metadata / Workflow | `VssWorkflow` | `vss_snapshot` | Yes | Yes | `COMPLETE` | VSS snapshot extraction workflow. |
| 42 | Credential Manager / Windows Vault + DPAPI | Yes | Yes | Signature (`DPAPI`) / Path (`Credentials`, `Vault`) | `DpapiVaultParser` | `dpapi_blob` | Yes | Yes | `COMPLETE` | Windows Vault and DPAPI structure parser. |
