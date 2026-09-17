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

SUSPICIOUS_PATH_PATTERNS = ("\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\users\\public\\", "c:\\temp\\", "c:\\tmp\\", "c:\\users\\public\\")
SUSPICIOUS_EXECUTABLES = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe")

KNOWN_LEGITIMATE_TASKS = (
    "cleanuptemporarystate",
    "ad rms rights policy template management",
    "programdataupdater",
)


class PersistenceAnalyzer:
    """
    Deterministic analyzer for endpoint persistence artifacts.
    """

    @staticmethod
    def is_suspicious_path(path_str: str) -> bool:
        p_lower = path_str.lower().replace("/", "\\")
        if any(pattern in p_lower for pattern in SUSPICIOUS_PATH_PATTERNS):
            return True
        if "\\temp\\" in p_lower or "\\tmp\\" in p_lower:
            return True
        return False

    @staticmethod
    def is_legitimate_autostart(val_name: str, val_data: str) -> bool:
        v_name_lower = val_name.lower()
        v_data_lower = val_data.lower()
        if "onedrive" in v_name_lower or "onedrive.exe" in v_data_lower:
            if "onedrive.exe" in v_data_lower:
                return True
        return False

    @staticmethod
    def is_legitimate_task(task_name: str, task_cmd: str, reg_key: str = "") -> bool:
        t_name_lower = task_name.lower()
        t_cmd_lower = task_cmd.lower()
        r_key_lower = reg_key.lower()

        if any(legit in t_name_lower or legit in t_cmd_lower or legit in r_key_lower for legit in KNOWN_LEGITIMATE_TASKS):
            return True
        if "\\microsoft\\windows\\" in t_cmd_lower or "\\microsoft\\windows\\" in r_key_lower:
            if not any(e in t_cmd_lower for e in SUSPICIOUS_EXECUTABLES):
                return True
        return False

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
                    ts = artifact.timestamp or datetime.now(timezone.utc)

                    if self.is_legitimate_autostart(val_name, val_data):
                        # Legitimate application auto-start entry (e.g. OneDrive) - skip creating threat finding
                        continue
                    else:
                        is_susp_path = self.is_suspicious_path(val_data)
                        is_susp_exe = any(e in val_data for e in SUSPICIOUS_EXECUTABLES)

                        if is_susp_path or is_susp_exe:
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
                        is_susp_path = self.is_suspicious_path(img_path)
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
                reg_key = (norm.registry_key or str(raw.get("key", "")) or str(raw.get("path", ""))).lower()

                if task_cmd or task_name or reg_key:
                    ts = artifact.timestamp or datetime.now(timezone.utc)

                    if self.is_legitimate_task(task_name, task_cmd, reg_key):
                        # Built-in Windows system task - skip creating threat finding
                        continue
                    else:
                        is_susp_path = self.is_suspicious_path(task_cmd)
                        is_susp_exe = any(e in task_cmd for e in SUSPICIOUS_EXECUTABLES)

                        if is_susp_path or is_susp_exe:
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
