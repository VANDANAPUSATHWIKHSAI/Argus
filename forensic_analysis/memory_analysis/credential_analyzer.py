"""
Memory Analysis — Credential Artifact Analyzer
===============================================
Analyzes memory credential structures (LSASS dumps, cached hashes, credential blobs):
- memory.lsass, memory.credentials, memory.hashdump, memory.lsadump

CRITICAL SECURITY REQUIREMENT:
Zero raw passwords, password hashes, secrets, or tokens are persisted.
Only safe metadata (PID, process name, structure presence) is recorded.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class CredentialAnalyzer:
    """
    Deterministic analyzer for memory credential artifacts with mandatory secret redaction.
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

            if art_type not in ("memory.lsass", "memory.credentials", "memory.hashdump", "memory.lsadump"):
                continue

            pid = norm.process_id or raw.get("PID") or raw.get("pid")
            proc_name = norm.process_name or str(raw.get("Process", "")) or "lsass.exe"
            struct_type = str(raw.get("type", "")) or str(raw.get("Plugin", "")) or "lsass_memory_structure"

            fact_msg = (
                f"Credential-related memory structure observed in process '{proc_name}' (PID {pid or 'N/A'}, "
                f"structure='{struct_type}'). Note: Raw credential secrets redacted per ARGUS security contract."
            )

            # Mandatory secret redaction check: Ensure metadata contains 0 raw credentials
            safe_metadata = {
                "pid": pid,
                "process_name": proc_name,
                "structure_type": struct_type,
                "redacted": True,
                "artifact_id": artifact.artifact_id,
            }

            findings.append(Finding(
                case_id=case_id,
                fact=fact_msg,
                confidence=0.92,
                severity="high",
                mitre_mapping="T1003",
                timestamp=ts,
                evidence_reference=fcr_ref or artifact.artifact_id,
                source_artifact_id=artifact.artifact_id,
                layer="memory.credential_analyzer",
                metadata=safe_metadata,
            ))

        return findings
