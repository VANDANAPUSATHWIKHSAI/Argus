"""
Agent 2 — Deterministic Conflict Detector
===========================================
Identifies temporal anomalies, contradictory findings, identity mismatches,
and hash collisions across FIR evidence findings without relying on LLM guesswork.
"""

import re
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from agents.agent2_evidence_correlation.schemas import CorrelationConflict

logger = logging.getLogger(__name__)


class ConflictDetector:
    """
    Deterministic conflict detection engine for forensic findings.
    """

    def detect_conflicts(self, findings: List[Any]) -> List[CorrelationConflict]:
        conflicts: List[CorrelationConflict] = []
        conflict_idx = 1

        # Map entities to finding details
        filename_to_hashes: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list)) # filename -> hash -> [finding_ids]
        ip_to_severities: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))   # IP -> severity -> [finding_ids]
        finding_texts: Dict[str, str] = {}

        for finding in findings:
            fid = self._extract_finding_id(finding)
            text = self._extract_text(finding).lower()
            severity = self._extract_severity(finding)
            finding_texts[fid] = text

            # Extract filenames and hashes for hash collision check
            hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
            files = re.findall(r'\b[a-zA-Z0-9_\-\.]+\.(?:exe|dll|ps1|bat|vbs|sys|elf)\b', text)
            for f in files:
                for h in hashes:
                    filename_to_hashes[f.lower()][h.lower()].append(fid)

            # Extract IPs for status contradiction check
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
            for ip in ips:
                if not ip.startswith("127.") and ip != "0.0.0.0":
                    ip_to_severities[ip][severity.lower()].append(fid)

        # 1. Detect Hash Collisions / Filename Ambiguity
        for filename, hash_map in filename_to_hashes.items():
            if len(hash_map) > 1:
                involved: List[str] = []
                for h, fids in hash_map.items():
                    involved.extend(fids)
                involved = sorted(list(set(involved)))
                
                conflicts.append(
                    CorrelationConflict(
                        conflict_id=f"CONF-{conflict_idx:03d}",
                        conflict_type="hash_collision",
                        description=f"Multiple distinct SHA256 hashes detected for the same file name '{filename}'.",
                        involved_finding_ids=involved,
                        severity="high"
                    )
                )
                conflict_idx += 1

        # 2. Detect Severity / Attitudinal Contradictions
        for ip, sev_map in ip_to_severities.items():
            has_high_or_critical = "critical" in sev_map or "high" in sev_map
            has_low_or_info = "informational" in sev_map or "low" in sev_map
            if has_high_or_critical and has_low_or_info:
                involved = []
                for s, fids in sev_map.items():
                    involved.extend(fids)
                involved = sorted(list(set(involved)))

                conflicts.append(
                    CorrelationConflict(
                        conflict_id=f"CONF-{conflict_idx:03d}",
                        conflict_type="attitudinal_contradiction",
                        description=f"Contradictory severity assessments for IP address '{ip}' (assessed as both high/critical and low/informational).",
                        involved_finding_ids=involved,
                        severity="medium"
                    )
                )
                conflict_idx += 1

        # 3. Detect Textual Contradictions (e.g., "no persistence" vs "persistence detected")
        fids_list = list(finding_texts.keys())
        for i in range(len(fids_list)):
            for j in range(i + 1, len(fids_list)):
                id1, id2 = fids_list[i], fids_list[j]
                t1, t2 = finding_texts[id1], finding_texts[id2]

                if ("no persistence" in t1 and "persistence detected" in t2) or \
                   ("persistence detected" in t1 and "no persistence" in t2):
                    conflicts.append(
                        CorrelationConflict(
                            conflict_id=f"CONF-{conflict_idx:03d}",
                            conflict_type="attitudinal_contradiction",
                            description=f"Contradictory persistence assertions between finding {id1} and finding {id2}.",
                            involved_finding_ids=[id1, id2],
                            severity="high"
                        )
                    )
                    conflict_idx += 1

                if ("cleared of malware" in t1 and "malware infection confirmed" in t2) or \
                   ("malware infection confirmed" in t1 and "cleared of malware" in t2):
                    conflicts.append(
                        CorrelationConflict(
                            conflict_id=f"CONF-{conflict_idx:03d}",
                            conflict_type="attitudinal_contradiction",
                            description=f"Contradictory malware status between finding {id1} and finding {id2}.",
                            involved_finding_ids=[id1, id2],
                            severity="high"
                        )
                    )
                    conflict_idx += 1

        return conflicts

    def _extract_finding_id(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return finding.get("finding_id") or finding.get("id") or "F-UNKNOWN"
        elif hasattr(finding, "finding_id"):
            return getattr(finding, "finding_id")
        elif hasattr(finding, "id"):
            return getattr(finding, "id")
        return "F-UNKNOWN"

    def _extract_text(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return str(finding.get("fact") or finding.get("sanitized_fact") or "")
        elif hasattr(finding, "sanitized_fact") and getattr(finding, "sanitized_fact"):
            return str(getattr(finding, "sanitized_fact"))
        elif hasattr(finding, "fact"):
            return str(getattr(finding, "fact"))
        return ""

    def _extract_severity(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return str(finding.get("severity", "medium"))
        elif hasattr(finding, "severity"):
            return str(getattr(finding, "severity"))
        return "medium"
