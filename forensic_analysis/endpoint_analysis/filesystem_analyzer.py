"""
Endpoint Analysis — Filesystem & Execution Artifact Analyzer
==============================================================
Analyzes filesystem, disk image, and execution-trace artifacts:
- Prefetch (execution evidence indicated)
- Amcache (application presence/registration evidence)
- ShimCache / AppCompatCache (cache presence; NOT proof of execution)
- MFT (filesystem record & timestamps)
- LNK Shortcuts & Jump Lists (shortcut & file interaction evidence)
- Recycle Bin (file deletion evidence)
- USN Journal (NTFS change log)
- Volume Shadow Copies (VSS snapshot creation/deletion evidence)

Strictly enforces forensic semantic boundaries (EXECUTION vs PRESENCE vs DELETION).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class FilesystemAnalyzer:
    """
    Deterministic analyzer for endpoint filesystem and execution artifacts.
    """

    def analyze(
        self,
        artifacts: List[Artifact],
        case_id: str,
        fcr_ref: Optional[str] = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        for artifact in artifacts:
            art_type = (artifact.artifact_type or "").lower()
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}
            ts = artifact.timestamp or datetime.now(timezone.utc)

            # 1. Prefetch Artifacts (Execution Indicated)
            if art_type in ("prefetch_entry", "endpoint.prefetch"):
                proc_name = norm.process_name or norm.file_name or str(raw.get("ExecutableName", "")) or str(raw.get("process_name", ""))
                run_count = raw.get("RunCount") or raw.get("run_count") or 1
                if proc_name:
                    fact_msg = (
                        f"Application execution indicated via Windows Prefetch artifact: process '{proc_name}' "
                        f"executed {run_count} time(s), last run timestamped at {ts.isoformat()}."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.95,
                        severity="high" if any(b in proc_name.lower() for b in ("cmd.exe", "powershell.exe", "certutil.exe")) else "medium",
                        mitre_mapping="T1059",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.filesystem_analyzer",
                        metadata={
                            "process_name": proc_name,
                            "run_count": run_count,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 2. Amcache Artifacts (Application Presence / Registration Evidence)
            elif art_type in ("amcache_entry", "endpoint.amcache", "registry.amcache"):
                app_name = norm.process_name or norm.file_name or str(raw.get("name", "")) or str(raw.get("ProgramName", ""))
                sha1_hash = norm.hash or str(raw.get("sha1", "")) or str(raw.get("FileSHA1", ""))
                if app_name or sha1_hash:
                    fact_msg = (
                        f"Application presence/registration recorded in Amcache hive: binary '{app_name or 'unnamed'}' "
                        f"(SHA1={sha1_hash or 'N/A'}) registered on endpoint. "
                        f"Note: Amcache establishes binary presence/installation evidence, not guaranteed execution timestamp."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.88,
                        severity="medium",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.filesystem_analyzer",
                        metadata={
                            "app_name": app_name,
                            "sha1": sha1_hash,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 3. ShimCache / AppCompatCache Artifacts (Cache Presence)
            elif art_type in ("shimcache_entry", "endpoint.shimcache"):
                img_name = norm.process_name or norm.file_name or str(raw.get("path", "")) or str(raw.get("FilePath", ""))
                if img_name:
                    fact_msg = (
                        f"Executable metadata cached in ShimCache / AppCompatCache: binary '{img_name}' "
                        f"recorded with file modification timestamp {ts.isoformat()}. "
                        f"Note: ShimCache presence indicates file presence/compatibility flag registration, not guaranteed execution."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.80,
                        severity="low",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.filesystem_analyzer",
                        metadata={
                            "image_name": img_name,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 4. MFT Records (File System Activity)
            elif art_type in ("mft_entry", "endpoint.mft"):
                file_name = norm.file_name or str(raw.get("FileName", "")) or str(raw.get("file_name", ""))
                file_path = norm.file_path or str(raw.get("FilePath", ""))
                is_deleted = norm.deleted if norm.deleted is not None else raw.get("IsDeleted", False)

                if file_name or file_path:
                    if is_deleted:
                        fact_msg = (
                            f"File deletion record in NTFS Master File Table (MFT): file '{file_name or file_path}' "
                            f"marked as deleted at {ts.isoformat()}."
                        )
                        sev = "medium"
                        mitre = "T1070.004"
                    else:
                        fact_msg = (
                            f"File system record observed in NTFS MFT: file '{file_name or file_path}' "
                            f"recorded with timestamp {ts.isoformat()}."
                        )
                        sev = "informational"
                        mitre = None

                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.90,
                        severity=sev,
                        mitre_mapping=mitre,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.filesystem_analyzer",
                        metadata={
                            "file_name": file_name,
                            "file_path": file_path,
                            "deleted": is_deleted,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 5. LNK Files & Jump Lists
            elif art_type in ("lnk_shortcut", "jumplist_entry", "endpoint.lnk", "endpoint.jumplist"):
                target_path = norm.file_path or str(raw.get("TargetPath", "")) or str(raw.get("target_path", ""))
                lnk_name = norm.file_name or str(raw.get("LocalPath", "")) or str(raw.get("file_name", ""))

                if target_path or lnk_name:
                    fact_msg = (
                        f"Shortcut / JumpList file interaction record: shortcut '{lnk_name or 'unnamed'}' "
                        f"targets file path '{target_path or 'N/A'}'."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.85,
                        severity="medium" if any(p in target_path.lower() for p in ("removable", "e:\\", "d:\\", "\\\\")) else "informational",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.filesystem_analyzer",
                        metadata={
                            "shortcut_name": lnk_name,
                            "target_path": target_path,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 6. Recycle Bin Artifacts (Deletion Evidence)
            elif art_type in ("recycle_bin_entry", "endpoint.recycle_bin"):
                del_file = norm.file_name or norm.file_path or str(raw.get("OriginalFileName", "")) or str(raw.get("file_name", ""))
                if del_file:
                    fact_msg = (
                        f"File deletion artifact in Windows Recycle Bin: file '{del_file}' "
                        f"moved to Recycle Bin / deleted at {ts.isoformat()}."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.95,
                        severity="medium",
                        mitre_mapping="T1070.004",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.filesystem_analyzer",
                        metadata={
                            "deleted_file": del_file,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 7. Volume Shadow Copies (VSS)
            elif art_type in ("vss_snapshot", "endpoint.vss"):
                snap_name = norm.file_path or norm.rule_name or str(raw.get("SnapshotPath", "")) or "VSS Snapshot"
                fact_msg = f"Volume Shadow Copy (VSS) snapshot record observed: '{snap_name}' at {ts.isoformat()}."
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.90,
                    severity="informational",
                    mitre_mapping=None,
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="endpoint.filesystem_analyzer",
                    metadata={
                        "snapshot_name": snap_name,
                        "artifact_id": artifact.artifact_id,
                    }
                ))

            # 8. USN Journal & File System Images
            elif art_type in ("usn_entry", "filesystem_entry", "endpoint.usn", "endpoint.filesystem", "file_record"):
                fname = norm.file_name or norm.file_path or str(raw.get("file_name", ""))
                reason = str(raw.get("Reason", "")) or str(raw.get("reason", ""))
                if fname:
                    fact_msg = (
                        f"NTFS USN change journal / File system record observed for '{fname}': "
                        f"reason='{reason or 'FILE_ACTIVITY'}' at {ts.isoformat()}."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.88,
                        severity="informational",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.filesystem_analyzer",
                        metadata={
                            "file_name": fname,
                            "reason": reason,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        return findings
