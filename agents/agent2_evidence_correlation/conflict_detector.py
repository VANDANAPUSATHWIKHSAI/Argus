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
    Provides O(n) indexed entity lookups to detect timestamp, host, user, process parent,
    artifact identity, persistence, malware status, severity, and network conflicts.
    """

    def detect_conflicts(self, findings: List[Any]) -> List[CorrelationConflict]:
        conflicts: List[CorrelationConflict] = []
        conflict_idx = 1

        # Indexed structures for O(n) lookups
        filename_to_hashes: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        ip_to_severities: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        pid_to_users: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        pid_to_ppids: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        artifact_to_hosts: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        artifact_to_timestamps: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

        persistence_findings: List[Tuple[str, str]] = [] # (fid, text)
        malware_findings: List[Tuple[str, str]] = []     # (fid, text)

        for finding in findings:
            fid = self._extract_finding_id(finding)
            text = self._extract_text(finding)
            text_lower = text.lower()
            severity = self._extract_severity(finding).lower()
            host = self._extract_host(finding)
            user = self._extract_user(finding)
            pid = self._extract_pid(finding)
            ppid = self._extract_ppid(finding)
            ts_str = self._extract_ts_str(finding)
            art_id = self._extract_artifact_id(finding) or fid

            # Index hashes and filenames
            hashes = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
            files = re.findall(r'\b[a-zA-Z0-9_\-\.]+\.(?:exe|dll|ps1|bat|vbs|sys|elf)\b', text_lower)
            for f in files:
                for h in hashes:
                    filename_to_hashes[f][h.lower()].append(fid)

            # Index IPs & severities
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
            for ip in ips:
                if not ip.startswith("127.") and ip != "0.0.0.0":
                    ip_to_severities[ip][severity].append(fid)

            # Index PID -> User & Parent PID
            if pid:
                if user:
                    pid_to_users[pid][user.lower()].append(fid)
                if ppid:
                    pid_to_ppids[pid][ppid].append(fid)

            # Index Artifact -> Host & Timestamps
            if art_id:
                if host:
                    artifact_to_hosts[art_id][host.lower()].append(fid)
                if ts_str:
                    artifact_to_timestamps[art_id][ts_str].append(fid)

            # Collect persistence and malware statements
            if "persistence" in text_lower:
                persistence_findings.append((fid, text_lower))
            if "malware" in text_lower or "cleared" in text_lower or "infected" in text_lower:
                malware_findings.append((fid, text_lower))

        # ── 1. Hash Collisions / Artifact Identity Conflicts ─────────────────
        for filename, hash_map in filename_to_hashes.items():
            if len(hash_map) > 1:
                involved = sorted(list({fid for fids in hash_map.values() for fid in fids}))
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

        # ── 2. User Attribution Conflicts ─────────────────────────────────────
        for pid, user_map in pid_to_users.items():
            if len(user_map) > 1:
                involved = sorted(list({fid for fids in user_map.values() for fid in fids}))
                users_str = ", ".join(user_map.keys())
                conflicts.append(
                    CorrelationConflict(
                        conflict_id=f"CONF-{conflict_idx:03d}",
                        conflict_type="user_attribution_conflict",
                        description=f"Process PID '{pid}' attributed to multiple distinct users ({users_str}).",
                        involved_finding_ids=involved,
                        severity="high"
                    )
                )
                conflict_idx += 1

        # ── 3. Process Parent Conflicts ───────────────────────────────────────
        for pid, ppid_map in pid_to_ppids.items():
            if len(ppid_map) > 1:
                involved = sorted(list({fid for fids in ppid_map.values() for fid in fids}))
                ppids_str = ", ".join(ppid_map.keys())
                conflicts.append(
                    CorrelationConflict(
                        conflict_id=f"CONF-{conflict_idx:03d}",
                        conflict_type="process_parent_conflict",
                        description=f"Process PID '{pid}' reported with contradictory parent PIDs ({ppids_str}).",
                        involved_finding_ids=involved,
                        severity="medium"
                    )
                )
                conflict_idx += 1

        # ── 4. Host Attribution Conflicts ─────────────────────────────────────
        for art_id, host_map in artifact_to_hosts.items():
            if len(host_map) > 1:
                involved = sorted(list({fid for fids in host_map.values() for fid in fids}))
                hosts_str = ", ".join(host_map.keys())
                conflicts.append(
                    CorrelationConflict(
                        conflict_id=f"CONF-{conflict_idx:03d}",
                        conflict_type="host_attribution_conflict",
                        description=f"Artifact/finding '{art_id}' associated with contradictory hostnames ({hosts_str}).",
                        involved_finding_ids=involved,
                        severity="high"
                    )
                )
                conflict_idx += 1

        # ── 5. Timestamp Conflicts ───────────────────────────────────────────
        for art_id, ts_map in artifact_to_timestamps.items():
            if len(ts_map) > 1:
                involved = sorted(list({fid for fids in ts_map.values() for fid in fids}))
                conflicts.append(
                    CorrelationConflict(
                        conflict_id=f"CONF-{conflict_idx:03d}",
                        conflict_type="timestamp_conflict",
                        description=f"Contradictory event timestamps reported for artifact/finding '{art_id}'.",
                        involved_finding_ids=involved,
                        severity="medium"
                    )
                )
                conflict_idx += 1

        # ── 6. Severity / Attitudinal Contradictions ─────────────────────────
        for ip, sev_map in ip_to_severities.items():
            has_high_or_critical = "critical" in sev_map or "high" in sev_map
            has_low_or_info = "informational" in sev_map or "low" in sev_map
            if has_high_or_critical and has_low_or_info:
                involved = sorted(list({fid for fids in sev_map.values() for fid in fids}))
                conflicts.append(
                    CorrelationConflict(
                        conflict_id=f"CONF-{conflict_idx:03d}",
                        conflict_type="severity_disagreement",
                        description=f"Contradictory severity assessments for IP address '{ip}' (assessed as both high/critical and low/informational).",
                        involved_finding_ids=involved,
                        severity="medium"
                    )
                )
                conflict_idx += 1

        # ── 7. File State / Persistence Disagreements (Indexed check) ────────
        no_pers = [f for f, t in persistence_findings if "no persistence" in t or "benign" in t]
        has_pers = [f for f, t in persistence_findings if "persistence detected" in t or "registry run" in t or "startup" in t]
        if no_pers and has_pers:
            conflicts.append(
                CorrelationConflict(
                    conflict_id=f"CONF-{conflict_idx:03d}",
                    conflict_type="persistence_disagreement",
                    description=f"Contradictory persistence assertions between findings {no_pers} and {has_pers}.",
                    involved_finding_ids=sorted(list(set(no_pers + has_pers))),
                    severity="high"
                )
            )
            conflict_idx += 1

        # ── 8. Malware Status Disagreements (Indexed check) ─────────────────
        cleared = [f for f, t in malware_findings if "cleared of malware" in t or "benign" in t]
        infected = [f for f, t in malware_findings if "malware infection confirmed" in t or "trojan" in t or "ransomware" in t]
        if cleared and infected:
            conflicts.append(
                CorrelationConflict(
                    conflict_id=f"CONF-{conflict_idx:03d}",
                    conflict_type="malware_status_disagreement",
                    description=f"Contradictory malware status assertions between findings {cleared} and {infected}.",
                    involved_finding_ids=sorted(list(set(cleared + infected))),
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

    def _extract_host(self, finding: Any) -> Optional[str]:
        val = None
        if isinstance(finding, dict):
            val = finding.get("host") or finding.get("hostname")
        else:
            val = getattr(finding, "host", None) or getattr(finding, "hostname", None)
        if val:
            return str(val)
        text = self._extract_text(finding)
        match = re.search(r'\bhost(?:name)?[:=\s]+([a-zA-Z0-9_\-\.]+)\b', text, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_user(self, finding: Any) -> Optional[str]:
        val = None
        if isinstance(finding, dict):
            val = finding.get("user") or finding.get("username")
        else:
            val = getattr(finding, "user", None) or getattr(finding, "username", None)
        if val:
            return str(val)
        text = self._extract_text(finding)
        match = re.search(r'\buser(?:name)?[:=\s]+([a-zA-Z0-9_\-\.]+)\b', text, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_pid(self, finding: Any) -> Optional[str]:
        text = self._extract_text(finding)
        match = re.search(r'\bpid[:=\s]+(\d+)\b', text, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_ppid(self, finding: Any) -> Optional[str]:
        text = self._extract_text(finding)
        match = re.search(r'\bppid[:=\s]+(\d+)\b', text, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_ts_str(self, finding: Any) -> Optional[str]:
        if isinstance(finding, dict):
            return str(finding.get("timestamp") or finding.get("created_at") or "")
        return str(getattr(finding, "timestamp", None) or getattr(finding, "created_at", None) or "")

    def _extract_artifact_id(self, finding: Any) -> Optional[str]:
        if isinstance(finding, dict):
            return finding.get("source_artifact_id") or finding.get("artifact_id")
        return getattr(finding, "source_artifact_id", None) or getattr(finding, "artifact_id", None)


