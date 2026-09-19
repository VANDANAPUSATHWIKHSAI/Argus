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

# Discovery, Reconnaissance, File Management & Execution Cmdlets
RECON_CMDLETS: Dict[str, Tuple[str, Optional[str], str]] = {
    "whoami": ("System Owner/User Discovery", "T1033", "low"),
    "ipconfig": ("System Network Configuration / IP Discovery", "T1016", "low"),
    "get-nettcpconnection": ("Active Network Connections Discovery", "T1049", "medium"),
    "get-computerinfo": ("System Information Discovery", "T1082", "low"),
    "get-localuser": ("Local User Account Discovery", "T1087", "medium"),
    "get-process": ("Process Discovery", "T1057", "low"),
    "get-service": ("System Service Discovery", "T1007", "low"),
    "get-childitem": ("File and Directory Discovery", "T1083", "informational"),
    "get-filehash": ("File Hash Calculation / Verification", None, "low"),
    "get-content": ("File Content Retrieval", None, "informational"),
    "set-location": ("Working Directory Navigation", None, "informational"),
    "new-item": ("File / Directory Creation", None, "informational"),
    "remove-item": ("File / Directory Deletion", None, "low"),
    "start-process": ("Process Spawning / Execution", "T1059.001", "medium"),
}

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
            ts = artifact.timestamp

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

            # 3. Discovery, Reconnaissance, and Command Execution Telemetry
            recon_matches = []
            for token, (name, mitre, default_sev) in RECON_CMDLETS.items():
                if re.search(rf"\b{re.escape(token)}\b", cmd_lower):
                    recon_matches.append((token, name, mitre, default_sev))

            if recon_matches:
                primary_token, primary_name, primary_mitre, primary_sev = recon_matches[0]
                fact_msg = (
                    f"PowerShell command activity observed: {primary_name} ({primary_token}). "
                    f"Command: '{cmd_line[:150]}'"
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.90,
                    severity=primary_sev,
                    mitre_mapping=primary_mitre,
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="log.powershell_analyzer",
                    metadata={
                        "cmdlet": primary_token,
                        "activity_type": primary_name,
                        "command_line": cmd_line,
                        "artifact_id": artifact.artifact_id,
                        "sequence_number": raw.get("sequence_number"),
                    }
                ))

        return findings

