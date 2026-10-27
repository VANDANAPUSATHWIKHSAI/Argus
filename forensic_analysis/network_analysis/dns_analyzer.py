"""
Network Analysis Engine — DNS Analyzer
=======================================
Analyzes normalized DNS query artifacts for DGA (Domain Generation Algorithms),
entropy anomalies, and DNS tunneling heuristics (TXT length/volume).
"""

from __future__ import annotations

import math
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

# Configurable Deterministic Thresholds
DEFAULT_ENTROPY_THRESHOLD = 3.8
DEFAULT_LABEL_LENGTH_THRESHOLD = 15
DEFAULT_TXT_LENGTH_THRESHOLD = 100
DEFAULT_TXT_VOLUME_THRESHOLD = 5


def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy score for a string (bits per symbol)."""
    if not text:
        return 0.0
    text_lower = text.lower()
    counts = Counter(text_lower)
    length = len(text_lower)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class DNSAnalyzer:
    """
    Analyzes normalized DNS logs (dns_query / network.dns) for deterministic
    DGA and DNS tunneling indicators.
    """

    def __init__(
        self,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        label_length_threshold: int = DEFAULT_LABEL_LENGTH_THRESHOLD,
        txt_length_threshold: int = DEFAULT_TXT_LENGTH_THRESHOLD,
        txt_volume_threshold: int = DEFAULT_TXT_VOLUME_THRESHOLD,
    ):
        self.entropy_threshold = entropy_threshold
        self.label_length_threshold = label_length_threshold
        self.txt_length_threshold = txt_length_threshold
        self.txt_volume_threshold = txt_volume_threshold

    def analyze(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Analyzes a set of DNS artifacts associated with an FCR/case.
        Returns a list of deterministic Finding objects.
        """
        findings: List[Finding] = []
        txt_records: List[Artifact] = []

        for artifact in artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            query_domain = norm.domain or raw.get("query") or raw.get("domain") or ""
            qtype = str(raw.get("qtype") or raw.get("query_type") or norm.registry_value or "").upper()

            if not query_domain:
                continue

            # Extract lowest subdomain label for entropy calculation
            labels = query_domain.split(".")
            subdomain_label = labels[0] if labels else query_domain

            entropy = calculate_shannon_entropy(subdomain_label)

            # 1. DGA / High-Entropy Subdomain / Suspicious TLD Check
            import re
            suspicious_tlds = (".cfd", ".top", ".xyz", ".club", ".buzz", ".monster", ".cyou", ".work", ".stream", ".cc", ".tk")
            is_suspicious_tld = any(query_domain.lower().endswith(tld) for tld in suspicious_tlds)
            is_dga_num = bool(re.search(r'[a-z]{4,}\d{3,}\.(com|net|org)', query_domain.lower()))
            is_high_entropy = (entropy >= self.entropy_threshold and len(subdomain_label) >= self.label_length_threshold)

            if is_high_entropy or is_suspicious_tld or is_dga_num:
                reason = "High-entropy subdomain" if is_high_entropy else ("Suspicious top-level domain (.cfd/.top/etc.)" if is_suspicious_tld else "Algorithmic DGA name pattern")
                fact_msg = (
                    f"{reason} observed in DNS query: domain='{query_domain}' "
                    f"(label='{subdomain_label}', entropy={entropy:.2f})."
                )
                ts = artifact.timestamp or datetime.now(timezone.utc)
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.88,
                    severity="high" if (is_suspicious_tld or is_dga_num or entropy > 4.2) else "medium",
                    mitre_mapping="T1568.002",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="network.dns_analyzer",
                    metadata={
                        "domain": query_domain,
                        "entropy": entropy,
                        "subdomain_label": subdomain_label,
                        "artifact_id": artifact.artifact_id,
                        "is_suspicious_tld": is_suspicious_tld,
                        "is_dga_num": is_dga_num,
                    }
                ))

            # 2. Track TXT records for DNS Tunneling Analysis
            if qtype == "TXT" or "TXT" in str(raw.get("answers", "")).upper() or qtype == "16":
                txt_records.append(artifact)

                # Individual excessive TXT record length check
                answers = str(raw.get("answers") or raw.get("rdata") or "")
                if len(answers) >= self.txt_length_threshold:
                    fact_msg = (
                        f"DNS tunneling indicator detected: excessive TXT record length "
                        f"({len(answers)} bytes, threshold >= {self.txt_length_threshold} bytes) "
                        f"for query '{query_domain}'"
                    )
                    ts = artifact.timestamp or datetime.now(timezone.utc)
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.90,
                        severity="high",
                        mitre_mapping="T1071.004",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="network.dns_analyzer",
                        metadata={
                            "domain": query_domain,
                            "txt_length": len(answers),
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        # 3. Excessive TXT Record Volume Check
        if len(txt_records) >= self.txt_volume_threshold:
            sample_art = txt_records[0]
            ts = sample_art.timestamp or datetime.now(timezone.utc)
            fact_msg = (
                f"DNS tunneling heuristic triggered: excessive TXT record volume "
                f"({len(txt_records)} TXT queries, threshold >= {self.txt_volume_threshold}) "
                f"observed within DNS session"
            )
            findings.append(Finding(
                case_id=case_id,
                fact=fact_msg,
                confidence=0.88,
                severity="high",
                mitre_mapping="T1071.004",
                timestamp=ts,
                evidence_reference=fcr_ref or sample_art.artifact_id,
                source_artifact_id=sample_art.artifact_id,
                layer="network.dns_analyzer",
                metadata={
                    "txt_query_count": len(txt_records),
                    "sample_artifact_id": sample_art.artifact_id,
                }
            ))

        return findings
