"""
Network Analysis Engine — TLS Analyzer
=======================================
Analyzes TLS handshake records (tls_session / network.tls) against a local,
cached JSON snapshot of the abuse.ch SSL/TLS JA3/JA3S fingerprint blacklist.

CRITICAL ARCHITECTURAL REQUIREMENT:
No live network requests are made during analysis. If JA3/JA3S fields are absent,
a warning is logged, lookup is skipped, and execution continues cleanly.
"""

from __future__ import annotations

import os
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

DEFAULT_BLACKLIST_PATH = os.path.join(os.path.dirname(__file__), "tls_blacklist.json")


class TLSAnalyzer:
    """
    Analyzes TLS artifacts against local abuse.ch JA3/JA3S fingerprint blacklist snapshots.
    """

    def __init__(self, blacklist_path: str = DEFAULT_BLACKLIST_PATH):
        self.blacklist_path = blacklist_path
        self.blacklisted_ja3: Dict[str, Dict[str, str]] = {}
        self.blacklisted_ja3s: Dict[str, Dict[str, str]] = {}
        self.snapshot_version = "UNKNOWN"
        self.snapshot_date = "UNKNOWN"
        self._load_blacklist()

    def _load_blacklist(self) -> None:
        """Loads local cached blacklist JSON snapshot fixture."""
        if not os.path.exists(self.blacklist_path):
            logger.warning(
                "TLSAnalyzer: Blacklist snapshot file '%s' not found. TLS blacklist lookup disabled.",
                self.blacklist_path
            )
            return

        try:
            with open(self.blacklist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.snapshot_version = data.get("snapshot_version", "2026.08.01")
            self.snapshot_date = data.get("snapshot_date", "2026-08-01")
            self.blacklisted_ja3 = data.get("blacklisted_ja3", {})
            self.blacklisted_ja3s = data.get("blacklisted_ja3s", {})
            logger.info(
                "TLSAnalyzer: Loaded abuse.ch blacklist snapshot version '%s' (%d JA3, %d JA3S entries).",
                self.snapshot_version, len(self.blacklisted_ja3), len(self.blacklisted_ja3s)
            )
        except Exception as e:
            logger.warning("TLSAnalyzer: Failed to parse blacklist snapshot '%s': %s", self.blacklist_path, e)

    def analyze(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Analyzes TLS artifacts for blacklisted JA3 / JA3S hashes.
        Logs warning and skips correlation if JA3/JA3S fields are missing.
        """
        findings: List[Finding] = []

        for artifact in artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            ja3 = raw.get("ja3") or raw.get("ja3_hash") or getattr(norm, "ja3", None)
            ja3s = raw.get("ja3s") or raw.get("ja3s_hash") or getattr(norm, "ja3s", None)

            if not ja3 and not ja3s:
                logger.warning(
                    "TLSAnalyzer: Artifact '%s' missing JA3/JA3S fields. Skipping TLS blacklist correlation.",
                    artifact.artifact_id
                )
                continue

            ts = artifact.timestamp or datetime.now(timezone.utc)
            dst = norm.dst_ip or norm.domain or norm.host or "UNKNOWN_DST"

            # Check JA3 match
            if ja3 and str(ja3).lower() in self.blacklisted_ja3:
                match_info = self.blacklisted_ja3[str(ja3).lower()]
                family = match_info.get("malware_family", "Malicious TLS Client")
                severity = match_info.get("severity", "critical")
                mitre = match_info.get("mitre_mapping", "T1573.002")

                fact_msg = (
                    f"Malicious TLS JA3 fingerprint matched against abuse.ch snapshot "
                    f"(version={self.snapshot_version}): JA3={ja3} linked to '{family}' "
                    f"communicating with destination '{dst}'."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.98,
                    severity=severity,
                    mitre_mapping=mitre,
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="network.tls_analyzer",
                    metadata={
                        "ja3": ja3,
                        "malware_family": family,
                        "destination": dst,
                        "snapshot_version": self.snapshot_version,
                        "artifact_id": artifact.artifact_id,
                    }
                ))

            # Check JA3S match
            if ja3s and str(ja3s).lower() in self.blacklisted_ja3s:
                match_info = self.blacklisted_ja3s[str(ja3s).lower()]
                family = match_info.get("malware_family", "Malicious TLS Server Response")
                severity = match_info.get("severity", "critical")
                mitre = match_info.get("mitre_mapping", "T1573.002")

                fact_msg = (
                    f"Malicious TLS JA3S server fingerprint matched against abuse.ch snapshot "
                    f"(version={self.snapshot_version}): JA3S={ja3s} linked to '{family}' "
                    f"from destination '{dst}'."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.98,
                    severity=severity,
                    mitre_mapping=mitre,
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="network.tls_analyzer",
                    metadata={
                        "ja3s": ja3s,
                        "malware_family": family,
                        "destination": dst,
                        "snapshot_version": self.snapshot_version,
                        "artifact_id": artifact.artifact_id,
                    }
                ))

        return findings
