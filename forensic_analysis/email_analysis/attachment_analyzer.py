"""
Email Analysis Engine — Attachment Analyzer
============================================
Deterministically analyzes email attachment metadata for risk indicators
such as executable types, macro-enabled formats, double extensions, and MIME mismatches.
"""

from __future__ import annotations

import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".pif", ".vbs", ".js", ".hda", ".cpl",
    ".ps1", ".com", ".msi", ".jar", ".hta", ".vbe", ".jse", ".wsf", ".wsh"
}

MACRO_OFFICE_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".docb"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".cab"
}


class AttachmentAnalyzer:
    """
    Analyzes email attachment metadata deterministically without execution
    or live scanning.
    """

    def analyze(
        self,
        artifact: Artifact,
        correlation_ids: List[str]
    ) -> List[Finding]:
        art_type = getattr(artifact, "artifact_type", "")
        if art_type not in ("email", "email_header", "email.header", "email.body", "email_message", "file_record"):
            return []

        findings: List[Finding] = []
        raw = getattr(artifact, "raw_fields", {}) or {}

        # Extract attachments list from artifact raw fields or if artifact itself is a file_record attachment
        attachments: List[Dict[str, Any]] = []
        if art_type == "file_record" and getattr(artifact, "source_tool", "") in ("python_email", "extract_msg"):
            attachments.append({
                "filename": raw.get("filename") or getattr(artifact.normalized_fields, "file_name", "") or "unnamed",
                "mimetype": raw.get("content_type") or raw.get("mimetype") or "",
                "sha256": raw.get("sha256") or getattr(artifact.normalized_fields, "hash", "") or "",
                "size_bytes": raw.get("size_bytes") or raw.get("size", 0),
            })
        else:
            raw_atts = raw.get("attachments", [])
            if isinstance(raw_atts, list):
                attachments.extend(raw_atts)

        for att in attachments:
            if not isinstance(att, dict):
                continue

            filename = str(att.get("filename") or att.get("name") or "").strip()
            if not filename:
                continue

            mimetype = str(att.get("mimetype") or att.get("content_type") or "").lower().strip()
            att_hash = str(att.get("sha256") or att.get("hash") or att.get("md5") or "").strip()

            filename_lower = filename.lower()
            ext = os.path.splitext(filename_lower)[1]

            # 1. Double Extension Detection (e.g. invoice.pdf.exe)
            parts = filename_lower.split(".")
            if len(parts) > 2:
                sec_ext = "." + parts[-1]
                prim_ext = "." + parts[-2]
                if sec_ext in EXECUTABLE_EXTENSIONS or sec_ext in MACRO_OFFICE_EXTENSIONS:
                    fact_msg = f"Double extension attachment observed: '{filename}' (primary extension '{prim_ext}', execution extension '{sec_ext}')"
                    findings.append(Finding(
                        case_id=artifact.case_id,
                        tenant_id=getattr(artifact, "tenant_id", "default"),
                        fact=fact_msg,
                        confidence=0.90,
                        severity="high",
                        mitre_mapping="T1566.001",
                        timestamp=artifact.timestamp or datetime.now(timezone.utc),
                        evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="email.attachment_analyzer",
                        contributing_correlation_ids=list(correlation_ids),
                        metadata={"filename": filename, "attachment_hash": att_hash, "mimetype": mimetype}
                    ))
                    continue

            # 2. Executable Extension Detection
            if ext in EXECUTABLE_EXTENSIONS:
                fact_msg = f"Executable attachment type observed: '{filename}' with extension '{ext}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.85,
                    severity="high",
                    mitre_mapping="T1566.001",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.attachment_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"filename": filename, "extension": ext, "attachment_hash": att_hash, "mimetype": mimetype}
                ))

            # 3. Macro-Enabled Office Format Detection
            elif ext in MACRO_OFFICE_EXTENSIONS:
                fact_msg = f"Macro-enabled Office attachment observed: '{filename}' with extension '{ext}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.80,
                    severity="medium",
                    mitre_mapping="T1566.001",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.attachment_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"filename": filename, "extension": ext, "attachment_hash": att_hash, "mimetype": mimetype}
                ))

            # 4. MIME / Filename Extension Mismatch
            if mimetype and (ext == ".pdf" and "pdf" not in mimetype and "octet-stream" in mimetype and "exe" in mimetype):
                fact_msg = f"Filename extension and MIME type mismatch observed: '{filename}' has extension '{ext}' but MIME type '{mimetype}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.85,
                    severity="medium",
                    mitre_mapping="T1566.001",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.attachment_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"filename": filename, "extension": ext, "mimetype": mimetype, "attachment_hash": att_hash}
                ))

            # 5. Encrypted Archive Metadata
            if att.get("is_encrypted") or att.get("encrypted"):
                fact_msg = f"Password-protected or encrypted archive attachment observed: '{filename}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.75,
                    severity="medium",
                    mitre_mapping="T1566.001",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.attachment_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"filename": filename, "encrypted": True, "attachment_hash": att_hash}
                ))

        return findings
