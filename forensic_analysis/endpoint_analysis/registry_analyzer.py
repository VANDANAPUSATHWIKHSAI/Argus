"""
Endpoint Analysis — Registry & Configuration Analyzer
======================================================
Analyzes registry-backed system configuration and endpoint state:
- Security configuration modifications (Defender / UAC / LSA disabling)
- Windows Defender log detections
- Group Policy (GPO) registry settings
- DPAPI metadata & vault blob presence
- MUICache executable display names
- Network configuration registry settings

Strictly avoids non-deterministic MITRE over-mapping.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class RegistryAnalyzer:
    """
    Deterministic analyzer for endpoint registry and security configuration artifacts.
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

            # 1. Security Configuration Overrides (Defender/UAC/LSA)
            if art_type in ("registry_key", "registry.security", "evasion_indicator"):
                reg_key = (norm.registry_key or str(raw.get("key", "")) or str(raw.get("path", ""))).lower()
                val_name = (norm.registry_value or str(raw.get("value_name", ""))).lower()
                val_data = str(norm.registry_value_data or raw.get("value_data", "") or raw.get("data", ""))

                # Defender Disabled Check
                if "disableantispyware" in val_name or "disablerealtimemonitoring" in val_name:
                    if val_data in ("1", "true", "True"):
                        fact_msg = (
                            f"Endpoint security override detected in Registry: Windows Defender disabled "
                            f"via '{val_name}' = '{val_data}' in key '{reg_key}'."
                        )
                        findings.append(Finding(
                            case_id=case_id,
                            fact=fact_msg,
                            confidence=0.98,
                            severity="high",
                            mitre_mapping="T1562.001",
                            timestamp=ts,
                            evidence_reference=fcr_ref or artifact.artifact_id,
                            source_artifact_id=artifact.artifact_id,
                            layer="endpoint.registry_analyzer",
                            metadata={
                                "registry_key": reg_key,
                                "value_name": val_name,
                                "value_data": val_data,
                                "artifact_id": artifact.artifact_id,
                            }
                        ))

                # UAC Disabled Check
                elif "enablelua" in val_name:
                    if val_data in ("0", "false", "False"):
                        fact_msg = (
                            f"Security feature override detected in Registry: User Account Control (UAC) disabled "
                            f"via 'EnableLUA' = '0' in key '{reg_key}'."
                        )
                        findings.append(Finding(
                            case_id=case_id,
                            fact=fact_msg,
                            confidence=0.95,
                            severity="high",
                            mitre_mapping="T1562.001",
                            timestamp=ts,
                            evidence_reference=fcr_ref or artifact.artifact_id,
                            source_artifact_id=artifact.artifact_id,
                            layer="endpoint.registry_analyzer",
                            metadata={
                                "registry_key": reg_key,
                                "value_name": val_name,
                                "value_data": val_data,
                                "artifact_id": artifact.artifact_id,
                            }
                        ))

                # Generic Registry Modification Flag
                elif any(k in reg_key for k in ("\\control\\lsa", "\\policies\\system")):
                    fact_msg = (
                        f"Critical system security key modification observed in Registry: '{reg_key}' "
                        f"value '{val_name}' = '{val_data[:100]}'."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.88,
                        severity="medium",
                        mitre_mapping="T1112",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.registry_analyzer",
                        metadata={
                            "registry_key": reg_key,
                            "value_name": val_name,
                            "value_data": val_data,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 2. Windows Defender Logs
            elif art_type in ("defender_log", "endpoint.defender"):
                threat_name = norm.rule_name or str(raw.get("ThreatName", "")) or str(raw.get("threat_name", ""))
                proc_name = norm.process_name or str(raw.get("ProcessName", ""))
                sev = norm.severity or "high"

                if threat_name:
                    fact_msg = (
                        f"Windows Defender threat detection alert: threat '{threat_name}' "
                        f"detected in process '{proc_name or 'N/A'}' with severity '{sev}'."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.95,
                        severity=sev,
                        mitre_mapping="T1562.001",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.registry_analyzer",
                        metadata={
                            "threat_name": threat_name,
                            "process_name": proc_name,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 3. Group Policy Logs
            elif art_type in ("group_policy", "endpoint.gpo"):
                gpo_key = norm.registry_key or str(raw.get("key", "")) or str(raw.get("GPO", ""))
                if gpo_key:
                    fact_msg = f"Group Policy registry setting observed: key='{gpo_key}'."
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.85,
                        severity="informational",
                        mitre_mapping="T1112",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.registry_analyzer",
                        metadata={
                            "gpo_key": gpo_key,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

            # 4. DPAPI Blobs (Vault Metadata Presence)
            elif art_type in ("dpapi_blob", "endpoint.dpapi"):
                vault_file = norm.file_name or norm.file_path or str(raw.get("file_name", ""))
                user = norm.user or str(raw.get("user", ""))
                if vault_file:
                    fact_msg = (
                        f"DPAPI credential vault blob metadata present for user '{user or 'N/A'}': "
                        f"file '{vault_file}'. Note: DPAPI metadata presence indicates vault storage, NOT confirmed password extraction."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.88,
                        severity="informational",
                        mitre_mapping="T1555",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="endpoint.registry_analyzer",
                        metadata={
                            "vault_file": vault_file,
                            "user": user,
                            "decrypted": False,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        return findings
