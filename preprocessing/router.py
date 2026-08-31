"""
Preprocessing Parser Router
===========================
Routes Evidence objects to the correct parser implementation using a layered detection strategy:
1. Security & Input Sanitization
2. Explicit evidence-type metadata (when supplied)
3. Magic-byte / signature detection (EVTX, PCAP, Registry, Memory, E01, SQLite, ESE, OLE, EML)
4. Known forensic filename & path patterns (NTUSER.DAT, $MFT, SRUDB.dat, ConsoleHost_history.txt, places.sqlite, etc.)
5. Extension fallback (.evtx, .pcap, .eml, .msg, .pf, .lnk, .wer, etc.)
6. Explicit UNSUPPORTED / AMBIGUOUS / UNKNOWN result handling

Preserves architectural separation between raw EVTX (EvtxECmd) and threat-hunted EVTX (Hayabusa),
and distinguishes acquisition workflows (VSS) from direct evidence parsers.
"""

from __future__ import annotations

import os
import re
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Any

from infrastructure.schemas import Evidence, AuditLogEntry
from preprocessing.parsers.evtx_parser import EvtxParser
from preprocessing.parsers.evtxecmd_parser import EvtxECmdParser
from preprocessing.parsers.memory_parser import MemoryParser
from preprocessing.parsers.pcap_parser import PcapParser
from preprocessing.parsers.registry_parser import RegistryParser
from preprocessing.parsers.browser_parser import BrowserParser
from preprocessing.parsers.email_parser import EmailParser
from preprocessing.parsers.filesystem_parser import FilesystemParser
from preprocessing.parsers.firefox_parser import FirefoxParser
from preprocessing.parsers.msg_parser import MsgEmailParser
from preprocessing.parsers.mftecmd_parser import MfteCmdMftParser
from preprocessing.parsers.pecmd_parser import PecmdPrefetchParser
from preprocessing.parsers.lecmd_parser import LecmdLnkParser
from preprocessing.parsers.jlecmd_parser import JlecmdJumpListParser
from preprocessing.parsers.rbcmd_parser import RbcmdRecycleBinParser
from preprocessing.parsers.amcache_parser import AmcacheParser
from preprocessing.parsers.srum_parser import SrumECmdParser
from preprocessing.parsers.usn_parser import UsnLogFileParser
from preprocessing.parsers.shimcache_parser import ShimCacheParser
from preprocessing.parsers.powershell_history_parser import PowerShellHistoryParser
from preprocessing.parsers.wmi_persistence_parser import WmiPersistenceParser
from preprocessing.parsers.timeline_parser import ActivitiesCacheParser
from preprocessing.parsers.stickynotes_parser import StickyNotesParser
from preprocessing.parsers.notification_parser import NotificationDbParser
from preprocessing.parsers.windows_search_parser import WindowsSearchParser
from preprocessing.parsers.wer_parser import WerReportParser
from preprocessing.parsers.firewall_parser import WindowsFirewallParser
from preprocessing.parsers.defender_parser import WindowsDefenderParser
from preprocessing.parsers.scheduled_task_parser import ScheduledTaskParser
from preprocessing.parsers.sbecmd_parser import SBECmdParser
from preprocessing.parsers.windows_update_parser import WindowsUpdateLogParser
from preprocessing.parsers.gpo_parser import GroupPolicyLogParser
from preprocessing.parsers.dpapi_parser import DpapiVaultParser
from preprocessing.parsers.vss_parser import VssWorkflow

logger = logging.getLogger(__name__)


class UnroutableEvidenceError(ValueError):
    """Raised when no suitable parser can be found for the given Evidence."""
    def __init__(
        self,
        evidence_id: str,
        metadata: dict,
        status: str = "UNKNOWN",
        reason: Optional[str] = None,
        detected_type: Optional[str] = None,
        target_parser: Optional[str] = None,
    ) -> None:
        self.evidence_id = evidence_id
        self.metadata = metadata
        self.status = status
        self.reason = reason
        self.detected_type = detected_type
        self.target_parser = target_parser
        msg = (
            f"No suitable parser could be found for evidence {evidence_id} "
            f"[status={status}, type={detected_type or 'unknown'}, parser={target_parser or 'none'}]. "
            f"Reason: {reason or 'No matching parser registered'}. Metadata: {metadata}"
        )
        super().__init__(msg)


@dataclass
class RoutingResult:
    """Structured routing outcome containing full provenance for downstream processing."""
    evidence_id: str
    case_id: str
    target_parser: str
    evidence_type: str
    detection_method: str
    status: str                # "ROUTED", "UNSUPPORTED", "AMBIGUOUS", "UNKNOWN"
    reason: Optional[str] = None
    parser_instance: Optional[object] = None


# Registry of implemented parsers
_IMPLEMENTED_PARSERS: dict[str, type] = {
    "EvtxParser": EvtxParser,
    "EvtxECmdParser": EvtxECmdParser,
    "MemoryParser": MemoryParser,
    "PcapParser": PcapParser,
    "RegistryParser": RegistryParser,
    "BrowserParser": BrowserParser,
    "EmailParser": EmailParser,
    "FilesystemParser": FilesystemParser,
    "FirefoxParser": FirefoxParser,
    "MsgEmailParser": MsgEmailParser,
    "MfteCmdMftParser": MfteCmdMftParser,
    "PecmdPrefetchParser": PecmdPrefetchParser,
    "LecmdLnkParser": LecmdLnkParser,
    "JlecmdJumpListParser": JlecmdJumpListParser,
    "RbcmdRecycleBinParser": RbcmdRecycleBinParser,
    "AmcacheParser": AmcacheParser,
    "SrumECmdParser": SrumECmdParser,
    "UsnLogFileParser": UsnLogFileParser,
    "ShimCacheParser": ShimCacheParser,
    "ScheduledTaskParser": ScheduledTaskParser,
    "SBECmdParser": SBECmdParser,
    "PowerShellHistoryParser": PowerShellHistoryParser,
    "WmiPersistenceParser": WmiPersistenceParser,
    "ActivitiesCacheParser": ActivitiesCacheParser,
    "StickyNotesParser": StickyNotesParser,
    "NotificationDbParser": NotificationDbParser,
    "WindowsSearchParser": WindowsSearchParser,
    "WerReportParser": WerReportParser,
    "WindowsUpdateLogParser": WindowsUpdateLogParser,
    "WindowsFirewallParser": WindowsFirewallParser,
    "WindowsDefenderParser": WindowsDefenderParser,
    "GroupPolicyLogParser": GroupPolicyLogParser,
    "DpapiVaultParser": DpapiVaultParser,
    "VssWorkflow": VssWorkflow,
}

# Known 42-Source Registration Target Map
_SOURCE_PARSER_MAP: dict[str, tuple[str, str]] = {
    "memory_dump": ("Memory Dump", "MemoryParser"),
    "pcap": ("PCAP / Network Traffic", "PcapParser"),
    "ids": ("Network Security / IDS", "PcapParser"),
    "evtx_raw": ("Windows Event Logs (EVTX) — raw", "EvtxECmdParser"),
    "evtx_hunted": ("Windows Event Logs (EVTX) — threat-hunted", "EvtxParser"),
    "registry": ("Windows Registry", "RegistryParser"),
    "chrome": ("Browser Artifacts — Chrome / Chromium", "BrowserParser"),
    "firefox": ("Browser Artifacts — Firefox", "FirefoxParser"),
    "eml": ("Email — .eml", "EmailParser"),
    "msg": ("Email — .msg / Outlook", "MsgEmailParser"),
    "mft": ("MFT / NTFS", "MfteCmdMftParser"),
    "prefetch": ("Prefetch", "PecmdPrefetchParser"),
    "lnk": ("LNK Files", "LecmdLnkParser"),
    "jumplists": ("Jump Lists", "JlecmdJumpListParser"),
    "recycle_bin": ("Recycle Bin", "RbcmdRecycleBinParser"),
    "amcache": ("Amcache", "AmcacheParser"),
    "srum": ("SRUM", "SrumECmdParser"),
    "filesystem": ("File System / Disk Image", "FilesystemParser"),
    "usn_journal": ("USN Journal / $LogFile", "UsnLogFileParser"),
    "shimcache": ("ShimCache / AppCompatCache", "ShimCacheParser"),
    "scheduled_tasks": ("Scheduled Tasks", "ScheduledTaskParser"),
    "powershell_history": ("PowerShell Command History", "PowerShellHistoryParser"),
    "userassist": ("UserAssist", "RegistryParser"),
    "recentdocs": ("RecentDocs", "RegistryParser"),
    "shellbags": ("ShellBags", "SBECmdParser"),
    "bam_dam": ("BAM / DAM", "RegistryParser"),
    "muicache": ("MUICache", "RegistryParser"),
    "services": ("Services", "RegistryParser"),
    "wmi_persistence": ("WMI Persistence", "WmiPersistenceParser"),
    "defender": ("Windows Defender Logs", "WindowsDefenderParser"),
    "firewall": ("Windows Firewall Logs", "WindowsFirewallParser"),
    "timeline": ("Windows Timeline / ActivitiesCache", "ActivitiesCacheParser"),
    "search": ("Windows Search History", "WindowsSearchParser"),
    "network_config": ("Network Configuration", "RegistryParser"),
    "sticky_notes": ("Windows Sticky Notes", "StickyNotesParser"),
    "notification_db": ("Windows Notification Database", "NotificationDbParser"),
    "wer": ("Windows Error Reporting (WER) Reports", "WerReportParser"),
    "windows_update": ("Windows Update / Patch History", "WindowsUpdateLogParser"),
    "gpo": ("Group Policy Application Logs", "GroupPolicyLogParser"),
    "sysmon": ("Sysmon Operational Logs", "EvtxParser"),
    "vss": ("Volume Shadow Copies (VSS)", "VssWorkflow"),
    "dpapi_vault": ("Credential Manager / Windows Vault + DPAPI", "DpapiVaultParser"),
}


class ParserRouter:
    """Routes an Evidence object to its corresponding parser implementation using layered precedence."""

    def route(self, evidence: Evidence) -> object:
        """Route the evidence to its matching parser instance.

        Returns:
            An instance of the routed parser (e.g. EvtxParser, MemoryParser, etc.).

        Raises:
            UnroutableEvidenceError: If no suitable implemented parser can be routed.
        """
        result = self.determine_routing(evidence)

        # Log decision to audit_log
        entry = AuditLogEntry(
            event="parser_routed",
            timestamp=datetime.now(timezone.utc),
            detail={
                "parser": result.target_parser,
                "evidence_type": result.evidence_type,
                "method": result.detection_method,
                "status": result.status,
                "reason": result.reason,
            }
        )
        if evidence.audit_log is None:
            evidence.audit_log = []
        evidence.audit_log.append(entry)

        if result.status == "ROUTED" and result.parser_instance is not None:
            logger.info(
                "Evidence %s routed to %s via %s (%s)",
                evidence.evidence_id,
                result.target_parser,
                result.detection_method,
                result.evidence_type,
            )
            return result.parser_instance

        # Unroutable, unsupported, or ambiguous
        raise UnroutableEvidenceError(
            evidence_id=evidence.evidence_id,
            metadata=evidence.metadata,
            status=result.status,
            reason=result.reason,
            detected_type=result.evidence_type,
            target_parser=result.target_parser,
        )

    def determine_routing(self, evidence: Evidence) -> RoutingResult:
        """Perform deterministic layered detection for an Evidence object."""
        case_id = getattr(evidence, "case_id", "") or ""
        evidence_id = evidence.evidence_id
        file_path = evidence.file_path or ""
        filename = evidence.filename or (os.path.basename(file_path) if file_path else "")
        metadata = evidence.metadata or {}

        # ── 1. Security & Input Sanitization ──────────────────────────────
        if "\x00" in file_path or "\x00" in filename:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="None", evidence_type="Unknown",
                detection_method="security_check", status="UNKNOWN",
                reason="Unsafe filename: null-byte injection detected"
            )

        # Path traversal warning check (non-blocking if file exists safely)
        if ".." in file_path and not os.path.exists(file_path):
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="None", evidence_type="Unknown",
                detection_method="security_check", status="UNKNOWN",
                reason="Unsafe path traversal detected"
            )

        path_lower = file_path.replace("/", "\\").lower()
        fn_lower = filename.lower()
        ext = os.path.splitext(fn_lower)[1]

        # ── 2. Layer 1: Explicit Metadata Precedence ─────────────────────
        explicit_type = metadata.get("evidence_type") or metadata.get("source_tool") or metadata.get("target_parser")
        if explicit_type:
            exp_key = str(explicit_type).lower()
            if exp_key in _SOURCE_PARSER_MAP:
                ev_name, parser_name = _SOURCE_PARSER_MAP[exp_key]
                inst = _instantiate_if_implemented(parser_name)
                status = "ROUTED" if inst is not None else "UNSUPPORTED"
                reason = None if inst is not None else f"Parser class {parser_name} is registered but not implemented yet"
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser=parser_name, evidence_type=ev_name,
                    detection_method="explicit_metadata", status=status,
                    reason=reason, parser_instance=inst
                )

        # ── 3. Layer 2: Magic-Byte / Signature Detection ──────────────────
        magic = b""
        if file_path and os.path.exists(file_path) and os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    magic = f.read(32)
            except Exception as e:
                logger.warning("Failed to read magic bytes from %s: %s", file_path, e)

        if magic:
            # DPAPI Blob Signature
            if magic.startswith(b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11") or b"\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb" in magic:
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="DpapiVaultParser", evidence_type="Credential Manager / Windows Vault + DPAPI",
                    detection_method="signature", status="ROUTED", parser_instance=DpapiVaultParser()
                )

            # Registry.pol: "PReg"
            if magic.startswith(b"PReg"):
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="GroupPolicyLogParser", evidence_type="Group Policy Application Logs",
                    detection_method="signature", status="ROUTED", parser_instance=GroupPolicyLogParser()
                )

            # EVTX: "ElfFile\x00"
            if magic.startswith(b"ElfFile\x00"):
                if metadata.get("stream") == "raw" or metadata.get("tool") == "evtxecmd":
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="EvtxECmdParser", evidence_type="Windows Event Logs (EVTX) — raw",
                        detection_method="signature", status="ROUTED", parser_instance=EvtxECmdParser()
                    )
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="EvtxParser", evidence_type="Windows Event Logs (EVTX) — threat-hunted",
                    detection_method="signature", status="ROUTED", parser_instance=EvtxParser()
                )

            # PCAP / PCAPNG
            if (magic.startswith(b"\xd4\xc3\xb2\xa1") or 
                magic.startswith(b"\xa1\xb2\xc3\xd4") or 
                magic.startswith(b"\x0a\x0d\x0d\x0a")):
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="PcapParser", evidence_type="PCAP / Network Traffic",
                    detection_method="signature", status="ROUTED", parser_instance=PcapParser()
                )

            # Registry Hive: starts with "regf"
            if magic.startswith(b"regf"):
                if fn_lower == "amcache.hve":
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="AmcacheParser", evidence_type="Amcache",
                        detection_method="signature", status="ROUTED", parser_instance=AmcacheParser()
                    )
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="RegistryParser", evidence_type="Windows Registry",
                    detection_method="signature", status="ROUTED", parser_instance=RegistryParser()
                )

            # Memory dump formats: PAGEDUMP, PAGEDU64, MDMP (minidump)
            if (magic.startswith(b"PAGEDUMP") or 
                magic.startswith(b"PAGEDU64") or 
                magic.startswith(b"MDMP")):
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="MemoryParser", evidence_type="Memory Dump",
                    detection_method="signature", status="ROUTED", parser_instance=MemoryParser()
                )

            # Filesystem E01: "LVF"
            if magic.startswith(b"LVF"):
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="FilesystemParser", evidence_type="File System / Disk Image",
                    detection_method="signature", status="ROUTED", parser_instance=FilesystemParser()
                )

            # Prefetch: "SCCA"
            if magic.startswith(b"SCCA"):
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="PecmdPrefetchParser", evidence_type="Prefetch",
                    detection_method="signature", status="ROUTED", parser_instance=PecmdPrefetchParser()
                )

            # SQLite 3 Database
            if magic.startswith(b"SQLite format 3\x00"):
                if "firefox" in path_lower or fn_lower in ("places.sqlite", "cookies.sqlite", "formhistory.sqlite"):
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="FirefoxParser", evidence_type="Browser Artifacts — Firefox",
                        detection_method="signature", status="ROUTED", parser_instance=FirefoxParser()
                    )
                if fn_lower == "activitiescache.db":
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="ActivitiesCacheParser", evidence_type="Windows Timeline / ActivitiesCache",
                        detection_method="signature", status="ROUTED", parser_instance=ActivitiesCacheParser()
                    )
                if fn_lower in ("plum.sqlite", "stickynotes.sqlite"):
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="StickyNotesParser", evidence_type="Windows Sticky Notes",
                        detection_method="signature", status="ROUTED", parser_instance=StickyNotesParser()
                    )
                if fn_lower == "wpndatabase.db":
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="NotificationDbParser", evidence_type="Windows Notification Database",
                        detection_method="signature", status="ROUTED", parser_instance=NotificationDbParser()
                    )
                # Generic / Chrome SQLite database
                if any(k in path_lower or k in fn_lower for k in ("chrome", "history", "cookies", "web data", "login data")):
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="BrowserParser", evidence_type="Browser Artifacts — Chrome / Chromium",
                        detection_method="extension", status="ROUTED", parser_instance=BrowserParser()
                    )

            # ESE Database Signature
            if len(magic) >= 8 and magic[4:8] == b"\xef\x22\x20\x00":
                if fn_lower == "windows.edb":
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="WindowsSearchParser", evidence_type="Windows Search History",
                        detection_method="signature", status="ROUTED", parser_instance=WindowsSearchParser()
                    )

            # OLE Compound Document (MSG / Office / Email)
            if magic.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                if fn_lower.endswith(".msg") or metadata.get("extension") == ".msg":
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="MsgEmailParser", evidence_type="Email — .msg / Outlook",
                        detection_method="signature", status="ROUTED", parser_instance=MsgEmailParser()
                    )
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="MsgEmailParser", evidence_type="Email — .msg / Outlook",
                    detection_method="signature", status="ROUTED", parser_instance=MsgEmailParser()
                )

            # EML Email ASCII headers check
            try:
                text = magic[:32].decode("ascii", errors="ignore")
                if re.match(r'^(?:From|Received|Subject|MIME-Version|Return-Path|Delivered-To):', text, re.IGNORECASE):
                    return RoutingResult(
                        evidence_id=evidence_id, case_id=case_id,
                        target_parser="EmailParser", evidence_type="Email — .eml",
                        detection_method="signature", status="ROUTED", parser_instance=EmailParser()
                    )
            except Exception:
                pass

        # ── 4. Layer 3: Known Forensic Filename & Path Patterns ───────────
        # Registry Hives
        if fn_lower in {"ntuser.dat", "usrclass.dat", "system", "software", "sam", "security", "system.dat", "software.dat"}:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="RegistryParser", evidence_type="Windows Registry",
                detection_method="extension", status="ROUTED", parser_instance=RegistryParser()
            )

        if fn_lower == "amcache.hve":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="AmcacheParser", evidence_type="Amcache",
                detection_method="extension", status="ROUTED", parser_instance=AmcacheParser()
            )

        if fn_lower == "$mft":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="MfteCmdMftParser", evidence_type="MFT / NTFS",
                detection_method="extension", status="ROUTED", parser_instance=MfteCmdMftParser()
            )

        if fn_lower in {"$usnjrnl", "$usnjrnl:$j"}:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="UsnLogFileParser", evidence_type="USN Journal / $LogFile",
                detection_method="extension", status="ROUTED", parser_instance=UsnLogFileParser()
            )

        if fn_lower == "$logfile":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="UsnLogFileParser", evidence_type="USN Journal / $LogFile",
                detection_method="extension", status="ROUTED", parser_instance=UsnLogFileParser()
            )

        if fn_lower in {"appcompatcache.bin", "shimcache.bin"} or "appcompatcache" in path_lower or "shimcache" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="ShimCacheParser", evidence_type="ShimCache / AppCompatCache",
                detection_method="extension", status="ROUTED", parser_instance=ShimCacheParser()
            )

        if fn_lower == "srudb.dat":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="SrumECmdParser", evidence_type="SRUM",
                detection_method="extension", status="ROUTED", parser_instance=SrumECmdParser()
            )

        if "system32\\tasks" in path_lower or "windows\\tasks" in path_lower or "\\tasks\\" in path_lower or "scheduledtasks" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="ScheduledTaskParser", evidence_type="Scheduled Tasks",
                detection_method="extension", status="ROUTED", parser_instance=ScheduledTaskParser()
            )

        if "shellbags" in path_lower or "sbecmd" in path_lower or "bagmrutest" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="SBECmdParser", evidence_type="ShellBags",
                detection_method="extension", status="ROUTED", parser_instance=SBECmdParser()
            )

        if fn_lower == "windowsupdate.log" or fn_lower == "cbs.log" or fn_lower == "reportingevents.log" or "windowsupdate" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="WindowsUpdateLogParser", evidence_type="Windows Update / Patch History",
                detection_method="extension", status="ROUTED", parser_instance=WindowsUpdateLogParser()
            )

        if fn_lower == "consolehost_history.txt" or "psreadline" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="PowerShellHistoryParser", evidence_type="PowerShell Command History",
                detection_method="extension", status="ROUTED", parser_instance=PowerShellHistoryParser()
            )

        if fn_lower == "objects.data" or "root\\subscription" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="WmiPersistenceParser", evidence_type="WMI Persistence",
                detection_method="extension", status="ROUTED", parser_instance=WmiPersistenceParser()
            )

        if fn_lower == "activitiescache.db":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="ActivitiesCacheParser", evidence_type="Windows Timeline / ActivitiesCache",
                detection_method="extension", status="ROUTED", parser_instance=ActivitiesCacheParser()
            )

        if fn_lower == "windows.edb" or fn_lower == "windowssearch.db" or "windowssearch" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="WindowsSearchParser", evidence_type="Windows Search History",
                detection_method="extension", status="ROUTED", parser_instance=WindowsSearchParser()
            )

        if fn_lower in {"plum.sqlite", "stickynotes.sqlite", "thresholdnotes.snt"} or "stickynotes" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="StickyNotesParser", evidence_type="Windows Sticky Notes",
                detection_method="extension", status="ROUTED", parser_instance=StickyNotesParser()
            )

        if fn_lower == "wpndatabase.db" or "wpn" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="NotificationDbParser", evidence_type="Windows Notification Database",
                detection_method="extension", status="ROUTED", parser_instance=NotificationDbParser()
            )

        if "firefox" in path_lower or fn_lower in ("places.sqlite", "cookies.sqlite", "formhistory.sqlite"):
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="FirefoxParser", evidence_type="Browser Artifacts — Firefox",
                detection_method="extension", status="ROUTED", parser_instance=FirefoxParser()
            )

        if fn_lower in {"pfirewall.log", "firewall.log"} or ("firewall" in path_lower and ext in {".log", ".txt"}):
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="WindowsFirewallParser", evidence_type="Windows Firewall Logs",
                detection_method="extension", status="ROUTED", parser_instance=WindowsFirewallParser()
            )

        if (fn_lower in {"gpesvc.log", "grouppolicy.log", "gpt.ini", "registry.pol", "gpreport.xml", "gpreport.html", "gpresult.xml", "gpresult.txt", "gpresult.json", "gpreport.json"}
            or ("grouppolicy" in path_lower and ext in {".log", ".txt", ".xml", ".json", ".ini", ".pol"})
            or "group policy" in path_lower
            or "\\gpo\\" in path_lower
            or "\\policies\\" in path_lower):
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="GroupPolicyLogParser", evidence_type="Group Policy Application Logs",
                detection_method="extension", status="ROUTED", parser_instance=GroupPolicyLogParser()
            )

        if (fn_lower in {"preferred", "policy.vpol", "schema.xml"}
            or ext in {".vcrd", ".vpol"}
            or "\\microsoft\\credentials\\" in path_lower
            or "/microsoft/credentials/" in path_lower
            or "\\microsoft\\protect\\" in path_lower
            or "/microsoft/protect/" in path_lower
            or "\\microsoft\\vault\\" in path_lower
            or "/microsoft/vault/" in path_lower):
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="DpapiVaultParser", evidence_type="Credential Manager / Windows Vault + DPAPI",
                detection_method="extension", status="ROUTED", parser_instance=DpapiVaultParser()
            )

        if fn_lower in {"mplog", "mplog.log"} or ("defender" in path_lower and ext in {".log", ".txt", ".json", ".xml"}):
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="WindowsDefenderParser", evidence_type="Windows Defender Logs",
                detection_method="extension", status="ROUTED", parser_instance=WindowsDefenderParser()
            )



        if fn_lower.startswith("$i") or fn_lower.startswith("$r") or "recycle.bin" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="RbcmdRecycleBinParser", evidence_type="Recycle Bin",
                detection_method="extension", status="ROUTED", parser_instance=RbcmdRecycleBinParser()
            )

        if "automaticdestinations-ms" in fn_lower or "customdestinations-ms" in fn_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="JlecmdJumpListParser", evidence_type="Jump Lists",
                detection_method="extension", status="ROUTED", parser_instance=JlecmdJumpListParser()
            )

        # Chrome/Chromium Browser directory or profile pattern
        if ("hindsight" in path_lower or "hindsight" in fn_lower or
            "chrome" in path_lower or "chrome" in fn_lower or
            "history" in fn_lower or "cookies" in fn_lower or
            "web data" in fn_lower or "login data" in fn_lower):
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="BrowserParser", evidence_type="Browser Artifacts — Chrome / Chromium",
                detection_method="extension", status="ROUTED", parser_instance=BrowserParser()
            )

        # ── 5. Layer 4: Extension Fallback ───────────────────────────────
        ext = (metadata.get("extension") or "").lower()
        if not ext and filename:
            ext = os.path.splitext(filename)[1].lower()

        mime_type = (metadata.get("mime_type") or "").lower()

        if ext == ".evtx":
            if "grouppolicy" in path_lower or "microsoft-windows-grouppolicy" in fn_lower or fn_lower.startswith("microsoft-windows-grouppolicy"):
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="GroupPolicyLogParser", evidence_type="Group Policy Application Logs",
                    detection_method="extension", status="ROUTED", parser_instance=GroupPolicyLogParser()
                )
            if "defender" in path_lower or "microsoft-windows-windows defender" in fn_lower or fn_lower.startswith("microsoft-windows-windows defender"):
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="WindowsDefenderParser", evidence_type="Windows Defender Logs",
                    detection_method="extension", status="ROUTED", parser_instance=WindowsDefenderParser()
                )
            if metadata.get("stream") == "raw" or metadata.get("tool") == "evtxecmd":
                return RoutingResult(
                    evidence_id=evidence_id, case_id=case_id,
                    target_parser="EvtxECmdParser", evidence_type="Windows Event Logs (EVTX) — raw",
                    detection_method="extension", status="ROUTED", parser_instance=EvtxECmdParser()
                )
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="EvtxParser", evidence_type="Windows Event Logs (EVTX) — threat-hunted",
                detection_method="extension", status="ROUTED", parser_instance=EvtxParser()
            )

        if ext in {".pcap", ".pcapng"} or mime_type in {"application/vnd.tcpdump.pcap", "application/x-pcapng"}:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="PcapParser", evidence_type="PCAP / Network Traffic",
                detection_method="extension", status="ROUTED", parser_instance=PcapParser()
            )

        if ext == ".xml":
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        hdr = f.read(2048)
                    if "<Task" in hdr or "http://schemas.microsoft.com/windows/2004/02/mit/task" in hdr:
                        return RoutingResult(
                            evidence_id=evidence_id, case_id=case_id,
                            target_parser="ScheduledTaskParser", evidence_type="Scheduled Tasks",
                            detection_method="signature", status="ROUTED", parser_instance=ScheduledTaskParser()
                        )
                except Exception:
                    pass

        if ext == ".reg":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="RegistryParser", evidence_type="Windows Registry",
                detection_method="extension", status="ROUTED", parser_instance=RegistryParser()
            )

        if ext == ".eml" or mime_type == "message/rfc822":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="EmailParser", evidence_type="Email — .eml",
                detection_method="extension", status="ROUTED", parser_instance=EmailParser()
            )

        if ext == ".msg" or mime_type == "application/vnd.ms-outlook":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="MsgEmailParser", evidence_type="Email — .msg / Outlook",
                detection_method="extension", status="ROUTED", parser_instance=MsgEmailParser()
            )

        if ext in {".e01", ".dd", ".img", ".iso"}:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="FilesystemParser", evidence_type="File System / Disk Image",
                detection_method="extension", status="ROUTED", parser_instance=FilesystemParser()
            )

        if ext == ".pf":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="PecmdPrefetchParser", evidence_type="Prefetch",
                detection_method="extension", status="ROUTED", parser_instance=PecmdPrefetchParser()
            )

        if ext == ".lnk":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="LecmdLnkParser", evidence_type="LNK Files",
                detection_method="extension", status="ROUTED", parser_instance=LecmdLnkParser()
            )

        if ext == ".wer" or fn_lower == "report.wer" or "reportarchive" in path_lower or "wer" in path_lower:
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="WerReportParser", evidence_type="Windows Error Reporting (WER) Reports",
                detection_method="extension", status="ROUTED", parser_instance=WerReportParser()
            )

        if ext in {".dmp", ".mem", ".vmem", ".sav"} or ("mem" in fn_lower or "phys" in fn_lower) and ext == ".raw":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="MemoryParser", evidence_type="Memory Dump",
                detection_method="extension", status="ROUTED", parser_instance=MemoryParser()
            )

        # Ambiguous .raw check (without memory context)
        if ext == ".raw":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="None", evidence_type="Ambiguous Raw Binary (.raw)",
                detection_method="extension", status="AMBIGUOUS",
                reason="Extension .raw is ambiguous (could be Memory Dump or Raw Disk Image). Explicit metadata required."
            )

        # Ambiguous / Generic .dat check
        if ext == ".dat":
            return RoutingResult(
                evidence_id=evidence_id, case_id=case_id,
                target_parser="None", evidence_type="Generic Data File (.dat)",
                detection_method="extension", status="AMBIGUOUS",
                reason="Generic .dat extension without registry hive signature or known filename is ambiguous."
            )

        # ── 6. Layer 5: Default Unknown ───────────────────────────────────
        return RoutingResult(
            evidence_id=evidence_id, case_id=case_id,
            target_parser="None", evidence_type="Unknown",
            detection_method="none", status="UNKNOWN",
            reason=f"No matching signature, filename pattern, or extension found for file: {filename}"
        )


def _instantiate_if_implemented(parser_name: str) -> Optional[object]:
    """Return an instance of the parser if implemented in ARGUS, else None."""
    cls = _IMPLEMENTED_PARSERS.get(parser_name)
    if cls:
        try:
            return cls()
        except Exception:
            return None
    return None
