"""
Endpoint Analysis — USB / Device Analyzer
==========================================
Analyzes USB hardware insertion, connection history, Vendor/Product IDs, and serial numbers.

Strictly enforces semantic boundaries:
- USB PRESENT != MALICIOUS
- USB CONNECTED != FILE TRANSFER
- USB CONNECTED != DATA EXFILTRATION
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class USBAnalyzer:
    """
    Deterministic analyzer for USB device artifacts.
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

            if art_type in ("usb_device", "endpoint.usb_device", "registry.usb"):
                vid = str(raw.get("vendor_id", "")) or str(raw.get("VID", "")) or "UNKNOWN_VID"
                pid = str(raw.get("product_id", "")) or str(raw.get("PID", "")) or "UNKNOWN_PID"
                serial = str(raw.get("serial", "")) or str(raw.get("SerialNumber", "")) or norm.rule_name or "UNKNOWN_SERIAL"
                drive = str(raw.get("drive_letter", "")) or str(raw.get("Volume", "")) or "N/A"

                fact_msg = (
                    f"USB mass storage device connection history recorded: Vendor ID='{vid}', "
                    f"Product ID='{pid}', Serial='{serial}', Drive Letter='{drive}'. "
                    f"Note: USB device history confirms hardware attachment to host, NOT file transfer or exfiltration."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.92,
                    severity="medium" if serial != "UNKNOWN_SERIAL" else "informational",
                    mitre_mapping="T1091" if drive != "N/A" else "T1200",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="endpoint.usb_analyzer",
                    metadata={
                        "vendor_id": vid,
                        "product_id": pid,
                        "serial_number": serial,
                        "drive_letter": drive,
                        "artifact_id": artifact.artifact_id,
                    }
                ))

        return findings
