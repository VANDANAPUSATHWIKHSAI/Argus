"""
Endpoint Analysis — User Activity Artifact Analyzer
=====================================================
Analyzes user activity artifacts:
- UserAssist (ROT13 decoded execution count & last run timestamps)
- ShellBags (folder browsing and interaction history)
- RecentDocs (recent document MRU history)
- SRUM (application resource usage)
- Windows Timeline (activity history)
- Search History (local search query history)
- Sticky Notes & Notifications (user content & toast notifications)
- WER Reports (application crash/fault reports)

Preserves evidence semantics and decodes ROT13 strings deterministically.
"""

from __future__ import annotations

import codecs
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class UserActivityAnalyzer:
    """
    Deterministic analyzer for endpoint user activity artifacts.
    """

    @staticmethod
    def decode_rot13(text: str) -> str:
        """Deterministically decode ROT13 text if present."""
        if not text:
            return ""
        try:
            return codecs.encode(text, "rot_13")
        except Exception:
            return text

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

            # 1. UserAssist (ROT13 Decoded Application Interaction)
            if art_type in ("registry.userassist", "endpoint.userassist") or (
                art_type == "registry_key" and "userassist" in (norm.registry_key or "").lower()
            ):
                raw_val = norm.process_name or norm.registry_value or str(raw.get("value_name", "")) or str(raw.get("value", ""))
                decoded_app = self.decode_rot13(raw_val) if raw_val else "UNKNOWN_APP"
                run_count = raw.get("run_count") or raw.get("RunCount") or 1

                if decoded_app:
                    fact_msg = (
                        f"GUI application interaction/execution recorded in UserAssist hive: "
                        f"application '{decoded_app}' executed {run_count} time(s), last run timestamped at {ts.isoformat()}."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.92,
                        severity="medium" if any(b in decoded_app.lower() for b in ("cmd.exe", "powershell.exe", "regedit.exe")) else "informational",
                        mitre_mapping="T1083",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.user_activity_analyzer",
                        metadata={
                            "raw_value": raw_val,
                            "decoded_app": decoded_app,
                            "run_count": run_count,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 2. ShellBags (Folder Interaction History)
            elif art_type in ("shellbag_entry", "endpoint.shellbags"):
                folder_path = norm.file_path or str(raw.get("AbsolutePath", "")) or str(raw.get("path", ""))
                if folder_path:
                    fact_msg = (
                        f"Folder navigation / interaction recorded in Windows ShellBags: "
                        f"folder path '{folder_path}' accessed at {ts.isoformat()}."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.88,
                        severity="informational",
                        mitre_mapping="T1083",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.user_activity_analyzer",
                        metadata={
                            "folder_path": folder_path,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 3. RecentDocs (Recent Document MRU History)
            elif art_type in ("endpoint.recentdocs") or (
                art_type == "registry_key" and "recentdocs" in (norm.registry_key or "").lower()
            ):
                doc_name = norm.file_name or norm.file_path or str(raw.get("value_data", "")) or str(raw.get("value", ""))
                if doc_name:
                    fact_msg = f"Recent document interaction recorded in RecentDocs MRU: document '{doc_name}'."
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.85,
                        severity="informational",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.user_activity_analyzer",
                        metadata={
                            "document_name": doc_name,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 4. SRUM (Resource Usage)
            elif art_type in ("srum_entry", "endpoint.srum"):
                app_name = norm.process_name or str(raw.get("exe_name", "")) or str(raw.get("AppId", ""))
                if app_name:
                    fact_msg = f"Application resource / network usage recorded in SRUM: application '{app_name}'."
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.85,
                        severity="informational",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.user_activity_analyzer",
                        metadata={
                            "app_name": app_name,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 5. Timeline & Search History
            elif art_type in ("timeline_activity", "search_history", "endpoint.timeline", "endpoint.search"):
                act_detail = norm.file_name or norm.url or str(raw.get("query", "")) or str(raw.get("DisplayText", ""))
                if act_detail:
                    fact_msg = f"User activity / search record in Windows Timeline/Search: '{act_detail}'."
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.85,
                        severity="informational",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.user_activity_analyzer",
                        metadata={
                            "activity_detail": act_detail,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 6. Sticky Notes & Notifications
            elif art_type in ("sticky_note", "notification", "endpoint.stickynotes"):
                note_text = norm.rule_name or str(raw.get("Text", "")) or str(raw.get("Payload", ""))
                if note_text:
                    fact_msg = f"User note / notification record observed: content snippet '{note_text[:100]}'."
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.80,
                        severity="informational",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.user_activity_analyzer",
                        metadata={
                            "snippet": note_text[:100],
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 7. WER Reports (Crash Logs)
            elif art_type in ("wer_report", "endpoint.wer"):
                fault_app = norm.process_name or str(raw.get("AppName", "")) or str(raw.get("file_name", ""))
                if fault_app:
                    fact_msg = f"Windows Error Reporting (WER) application crash log recorded: application '{fault_app}' faulted."
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.90,
                        severity="low",
                        mitre_mapping=None,
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.user_activity_analyzer",
                        metadata={
                            "faulting_app": fault_app,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        return findings
