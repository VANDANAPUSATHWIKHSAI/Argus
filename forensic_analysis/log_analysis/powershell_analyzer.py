"""
Log Analysis Engine — PowerShell Analyzer
==========================================
Analyzes PowerShell script execution and command line telemetry for encoded commands,
obfuscation, and suspicious high-signal cmdlets using deterministic regex matching.

ARCHITECTURAL & NO-ML JUSTIFICATION:
This analyzer intentionally uses deterministic regex and inert textual parsing rather than
a machine learning model. Command-line parameters (-enc, -EncodedCommand, IEX, DownloadString)
are exact, deterministic forensic indicators. Deterministic rule scoring guarantees reproducible
results across forensic runs without non-deterministic model variation or hallucination risks.

SECURITY REQUIREMENT:
If Base64 decoding is performed, it is strictly TEXTUAL AND INERT.
Decoded payloads are never executed.
"""

from __future__ import annotations

import re
import base64
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

# High-Signal Suspicious Cmdlets and Keywords
SUSPICIOUS_CMDLETS = [
    "invoke-expression",
    "iex",
    "downloadstring",
    "downloadfile",
    "net.webclient",
    "bypass",
    "nop",
    "encodedcommand",
    "windowstyle hidden",
    "reflection.assembly",
    "memorystream",
]

# Encoded Command Flags
ENCODED_FLAGS_REGEX = re.compile(r"-(?:enc|encodedcommand|e|en)\b", re.IGNORECASE)


def try_inert_base64_decode(text: str) -> Optional[str]:
    """
    Attempts purely textual Base64 decoding of encoded PowerShell payloads.
    Returns decoded UTF-16LE or UTF-8 text string if successful; otherwise None.
    NEVER executes the decoded text.
    """
    if not text:
        return None
    try:
        # Extract potential base64 string tokens (min length 16)
        b64_matches = re.findall(r"[A-Za-z0-9+/=]{16,}", text)
        for token in b64_matches:
            raw_bytes = base64.b64decode(token)
            # PowerShell -enc uses UTF-16LE encoding
            try:
                decoded_str = raw_bytes.decode("utf-16le")
                if any(k in decoded_str.lower() for k in ("invoke", "http", "cmd", "script")):
                    return decoded_str
            except (UnicodeDecodeError, AttributeError):
                pass
            try:
                decoded_str = raw_bytes.decode("utf-8")
                if any(k in decoded_str.lower() for k in ("invoke", "http", "cmd", "script")):
                    return decoded_str
            except (UnicodeDecodeError, AttributeError):
                pass
    except Exception:
        pass
    return None


class PowerShellAnalyzer:
    """
    Analyzes PowerShell command lines and scriptblock logs for malicious execution.
    """

    def analyze(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Analyzes PowerShell artifacts and returns deterministic Findings.
        """
        findings: List[Finding] = []

        for artifact in artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            cmd_line = norm.process_command_line or raw.get("command_line") or raw.get("ScriptBlockText") or ""
            if not cmd_line:
                continue

            cmd_lower = cmd_line.lower()
            ts = artifact.timestamp or datetime.now(timezone.utc)

            # 1. Encoded Command Detection
            has_encoded_flag = bool(ENCODED_FLAGS_REGEX.search(cmd_line))
            decoded_payload = try_inert_base64_decode(cmd_line) if has_encoded_flag else None

            if has_encoded_flag:
                fact_msg = (
                    f"Encoded PowerShell command execution detected: flag '-enc/-EncodedCommand' present. "
                    f"Command snippet: '{cmd_line[:120]}'"
                )
                if decoded_payload:
                    fact_msg += f" (Inert textual decode snippet: '{decoded_payload[:100]}')"

                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.92,
                    severity="high",
                    mitre_mapping="T1059.001",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="log.powershell_analyzer",
                    metadata={
                        "command_line": cmd_line,
                        "has_encoded_flag": True,
                        "decoded_payload_snippet": decoded_payload[:150] if decoded_payload else None,
                        "artifact_id": artifact.artifact_id,
                    }
                ))

            # 2. High-Signal Cmdlet Keyword Analysis
            matched_cmdlets = [k for k in SUSPICIOUS_CMDLETS if k in cmd_lower]
            if matched_cmdlets:
                fact_msg = (
                    f"Suspicious PowerShell cmdlet/keyword pattern detected: "
                    f"cmdlets={matched_cmdlets} observed in script execution snippet: '{cmd_line[:150]}'"
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.88,
                    severity="high" if len(matched_cmdlets) >= 2 else "medium",
                    mitre_mapping="T1059.001",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="log.powershell_analyzer",
                    metadata={
                        "matched_cmdlets": matched_cmdlets,
                        "command_line": cmd_line,
                        "artifact_id": artifact.artifact_id,
                    }
                ))

        return findings
