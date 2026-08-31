"""
Endpoint Analysis — Persistence Analyzer
=========================================
Analyzes endpoint persistence mechanisms:
- Registry Run / RunOnce keys
- Startup locations
- Windows Service ImagePath definitions
- Scheduled Tasks
- WMI Event Consumers

Produces deterministic Finding records.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)

SUSPICIOUS_PATH_PATTERNS = ("appdata", "temp", "tmp", "users\\public", "programdata")
SUSPICIOUS_EXECUTABLES = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe")


class PersistenceAnalyzer:
    """
    Deterministic analyzer for endpoint persistence artifacts.
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

            # 1. Registry Run / RunOnce & Startup
            if art_type in ("registry_key", "registry.run", "evasion_indicator"):
                reg_key = (norm.registry_key or str(raw.get("key", "")) or str(raw.get("path", ""))).lower()
                val_data = (norm.registry_value_data or str(raw.get("value_data", "")) or str(raw.get("data", ""))).lower()
                val_name = (norm.registry_value or str(raw.get("value_name", ""))).lower()

                if any(k in reg_key for k in ("\\run", "\\runonce", "\\startup")):
                    is_susp_path = any(p in val_data for p in SUSPICIOUS_PATH_PATTERNS)
                    is_susp_exe = any(e in val_data for e in SUSPICIOUS_EXECUTABLES)

                    if is_susp_path or is_susp_exe:
                        ts = artifact.timestamp or datetime.now(timezone.utc)
                        fact_msg = (
                            f"Registry persistence entry detected in '{reg_key}': value '{val_name}' "
                            f"points to suspicious path/command: '{val_data[:150]}'"
                        )
                        findings.append(Finding(
                            case_id=case_id,
                            fact=fact_msg,
                            confidence=0.95 if (is_susp_path and is_susp_exe) else 0.88,
                            severity="high",
                            mitre_mapping="T1547.001",
                            timestamp=ts,
                            evidence_reference=fcr_ref or artifact.artifact_id,
                            source_artifact_id=artifact.artifact_id,
                            layer="endpoint.persistence_analyzer",
                            metadata={
                                "registry_key": reg_key,
                                "value_name": val_name,
                                "value_data": val_data,
                                "artifact_id": artifact.artifact_id,
                            }
                        ))

            # 2. Windows Services Persistence
            if art_type in ("registry_key", "registry.services", "endpoint.service"):
                reg_key = (norm.registry_key or str(raw.get("key", "")) or str(raw.get("path", ""))).lower()
                img_path = (norm.process_command_line or norm.file_path or str(raw.get("image_path", "")) or str(raw.get("ImagePath", ""))).lower()

                if "\\services\\" in reg_key or "imagepath" in str(raw):
                    if img_path:
                        is_susp_path = any(p in img_path for p in SUSPICIOUS_PATH_PATTERNS)
                        is_susp_exe = any(e in img_path for e in SUSPICIOUS_EXECUTABLES)

                        if is_susp_path or is_susp_exe:
                            ts = artifact.timestamp or datetime.now(timezone.utc)
                            fact_msg = (
                                f"Windows Service auto-start persistence detected for key '{reg_key}': "
                                f"service ImagePath points to suspicious binary: '{img_path[:150]}'"
                            )
                            findings.append(Finding(
                                case_id=case_id,
                                fact=fact_msg,
                                confidence=0.92,
                                severity="high",
                                mitre_mapping="T1543.003",
                                timestamp=ts,
                                evidence_reference=fcr_ref or artifact.artifact_id,
                                source_artifact_id=artifact.artifact_id,
                                layer="endpoint.persistence_analyzer",
                                metadata={
                                    "service_key": reg_key,
                                    "image_path": img_path,
                                    "artifact_id": artifact.artifact_id,
                                }
                            ))

            # 3. Scheduled Tasks
            if art_type in ("scheduled_task", "endpoint.task"):
                task_cmd = (norm.process_command_line or str(raw.get("action", "")) or str(raw.get("Command", ""))).lower()
                task_name = (norm.process_name or str(raw.get("task_name", "")) or str(raw.get("Name", ""))).lower()

                if task_cmd:
                    is_susp_path = any(p in task_cmd for p in SUSPICIOUS_PATH_PATTERNS)
                    is_susp_exe = any(e in task_cmd for e in SUSPICIOUS_EXECUTABLES)

                    if is_susp_path or is_susp_exe:
                        ts = artifact.timestamp or datetime.now(timezone.utc)
                        fact_msg = (
                            f"Scheduled task persistence detected for task '{task_name}': "
                            f"action command line points to script/suspicious location: '{task_cmd[:150]}'"
                        )
                        findings.append(Finding(
                            case_id=case_id,
                            fact=fact_msg,
                            confidence=0.90,
                            severity="high",
                            mitre_mapping="T1053.005",
                            timestamp=ts,
                            evidence_reference=fcr_ref or artifact.artifact_id,
                            source_artifact_id=artifact.artifact_id,
                            layer="endpoint.persistence_analyzer",
                            metadata={
                                "task_name": task_name,
                                "command_line": task_cmd,
                                "artifact_id": artifact.artifact_id,
                            }
                        ))

            # 4. WMI Event Consumers
            if art_type in ("wmi_event_consumer", "endpoint.wmi"):
                cmd_template = (norm.process_command_line or str(raw.get("command_line_template", "")) or str(raw.get("ScriptText", ""))).lower()
                consumer_name = (str(raw.get("Name", "")) or str(raw.get("consumer_name", ""))).lower()

                if cmd_template or raw:
                    ts = artifact.timestamp or datetime.now(timezone.utc)
                    fact_msg = (
                        f"WMI Event Consumer persistence artifact observed: consumer '{consumer_name or 'unnamed'}' "
                        f"configured with command/script template: '{cmd_template[:150]}'"
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.95,
                        severity="high",
                        mitre_mapping="T1546.003",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.persistence_analyzer",
                        metadata={
                            "consumer_name": consumer_name,
                            "command_template": cmd_template,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        return findings
