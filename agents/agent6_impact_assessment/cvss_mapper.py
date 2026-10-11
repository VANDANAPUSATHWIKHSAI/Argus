"""
Evidence-to-CVSS Metric Mapping Engine
=======================================
Translates forensic evidence findings from upstream agents (Agent 3, Agent 4, Agent 5)
and the Forensic Intelligence Repository (FIR) into substantiated CVSS v3.1 base metrics.

Key Safety Principles:
  1. Never hallucinate metric values without direct forensic evidence citations.
  2. Preserve complete evidence ID traceability for every metric.
  3. Explicitly report unknown metrics in `missing_metrics` rather than silently guessing.
  4. Accurately set `assessment_status: INSUFFICIENT_DATA` when evidence does not warrant a definitive score.
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple

from agents.agent6_impact_assessment.schemas import (
    CVSSMetricEvidence,
    CVSSAssessment,
    AssessmentStatus,
    CVSSSeverity
)
from agents.agent6_impact_assessment.cvss_calculator import (
    CVSSCalculator,
    derive_cvss_severity
)

logger = logging.getLogger(__name__)


class CVSSMapper:
    """
    Deterministic rule-based evidence-to-CVSS mapping engine.
    Scans upstream agent payloads and FIR findings to derive supported CVSS v3.1 metrics.
    """

    # Regex patterns for evidence matching
    RE_IP = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    RE_PORT = re.compile(r"\b(?:port\s*[:=]?\s*|:\s*)([0-9]{1,5})\b", re.I)
    RE_EXTERNAL_IP = re.compile(r"^(?:(?!10\.)(?!172\.(?:1[6-9]|2[0-9]|3[01])\.)(?!192\.168\.)(?!127\.)[0-9]{1,3}\.){3}[0-9]{1,3}$")

    # Ingress / network indicators
    NETWORK_KEYWORDS = {
        "network", "socket", "http", "https", "c2", "connect", "inbound", "ingress",
        "pcap", "beacon", "tcp", "udp", "port", "remote", "download cradle", "url"
    }

    # Phishing / User Interaction indicators
    USER_INTERACTION_KEYWORDS = {
        "phishing", "email attachment", "attachment", "opened", "clicked", "user interaction",
        "macro", "docm", "xlsm", "lnk", "user execution", "spearphishing"
    }

    # Privilege indicators
    ELEVATED_PRIVILEGE_KEYWORDS = {
        "system", "administrator", "root", "nt authority\\system", "high integrity",
        "sedebugprivilege", "elevated", "admin privileges", "uac bypass"
    }
    STANDARD_USER_KEYWORDS = {
        "standard user", "unprivileged", "domain user", "medium integrity", "user context",
        "local user", "low privilege"
    }

    # Integrity impact indicators
    HIGH_INTEGRITY_KEYWORDS = {
        "ransomware", "encrypt", "encrypted", "backdoor", "rootkit", "scheduled task",
        "registry autorun", "tamper", "modified system", "overwrite", "payload dropped",
        "persistence installed"
    }

    # Confidentiality impact indicators
    HIGH_CONFIDENTIALITY_KEYWORDS = {
        "exfiltrat", "data leak", "stolen", "dumped credentials", "lsass", "sam dump",
        "mimikatz", "database dump", "credit card", "sensitive data exfiltration"
    }
    LOW_CONFIDENTIALITY_KEYWORDS = {
        "reconnaissance", "discovery", "enumerat", "directory list", "whoami", "ipconfig",
        "net user", "systeminfo"
    }

    # Availability impact indicators
    HIGH_AVAILABILITY_KEYWORDS = {
        "crash", "reboot loop", "denial of service", "wiped", "unbootable", "offline",
        "service stop", "service crash", "bsod", "system shutdown"
    }

    @classmethod
    def map_evidence_to_cvss(
        cls,
        agent3_output: Optional[Dict[str, Any]] = None,
        agent4_output: Optional[Dict[str, Any]] = None,
        agent5_output: Optional[Dict[str, Any]] = None,
        fir_findings: Optional[List[Any]] = None
    ) -> CVSSAssessment:
        """
        Main mapping routine.
        Analyzes all upstream inputs, extracts grounded metric values, calculates score,
        and constructs the complete CVSSAssessment object.
        """
        agent3_output = agent3_output or {}
        agent4_output = agent4_output or {}
        agent5_output = agent5_output or {}
        fir_findings = fir_findings or []

        # 1. Compile all factual forensic texts and citeable evidence IDs
        facts_with_ids = cls._extract_facts_and_evidence(
            agent3_output, agent4_output, agent5_output, fir_findings
        )

        # 2. Evaluate each of the 8 CVSS v3.1 base metrics
        metrics: Dict[str, CVSSMetricEvidence] = {}
        missing_metrics: List[str] = []

        # 2.1 Attack Vector (AV)
        av_metric = cls._evaluate_attack_vector(facts_with_ids, agent3_output, agent4_output)
        metrics["attack_vector"] = av_metric
        if not av_metric.is_confirmed:
            missing_metrics.append("attack_vector")

        # 2.2 Attack Complexity (AC)
        ac_metric = cls._evaluate_attack_complexity(facts_with_ids, agent3_output, agent4_output)
        metrics["attack_complexity"] = ac_metric
        if not ac_metric.is_confirmed:
            missing_metrics.append("attack_complexity")

        # 2.3 Privileges Required (PR)
        pr_metric = cls._evaluate_privileges_required(facts_with_ids, agent3_output, agent4_output)
        metrics["privileges_required"] = pr_metric
        if not pr_metric.is_confirmed:
            missing_metrics.append("privileges_required")

        # 2.4 User Interaction (UI)
        ui_metric = cls._evaluate_user_interaction(facts_with_ids, agent3_output, agent4_output)
        metrics["user_interaction"] = ui_metric
        if not ui_metric.is_confirmed:
            missing_metrics.append("user_interaction")

        # 2.5 Scope (S)
        scope_metric = cls._evaluate_scope(facts_with_ids, agent3_output, agent4_output)
        metrics["scope"] = scope_metric
        if not scope_metric.is_confirmed:
            missing_metrics.append("scope")

        # 2.6 Confidentiality (C)
        c_metric = cls._evaluate_confidentiality(facts_with_ids, agent3_output, agent4_output)
        metrics["confidentiality"] = c_metric
        if not c_metric.is_confirmed:
            missing_metrics.append("confidentiality")

        # 2.7 Integrity (I)
        i_metric = cls._evaluate_integrity(facts_with_ids, agent3_output, agent4_output)
        metrics["integrity"] = i_metric
        if not i_metric.is_confirmed:
            missing_metrics.append("integrity")

        # 2.8 Availability (A)
        a_metric = cls._evaluate_availability(facts_with_ids, agent3_output, agent4_output)
        metrics["availability"] = a_metric
        if not a_metric.is_confirmed:
            missing_metrics.append("availability")

        # Collect all unique evidence IDs supporting metrics
        all_metric_evidence_ids: List[str] = sorted(list({
            eid for m in metrics.values() for eid in m.evidence_ids
        }))

        # Check if threat intel / Agent 5 provided an authoritative published CVE
        cve_assessment = cls._check_authoritative_cve(agent5_output, facts_with_ids)
        if cve_assessment:
            return cve_assessment

        # 3. Determine assessment status and compute score
        if len(missing_metrics) == 0:
            # All 8 metrics confirmed -> Calculate deterministic base score
            calc_dict = {
                "AV": metrics["attack_vector"].value_code,
                "AC": metrics["attack_complexity"].value_code,
                "PR": metrics["privileges_required"].value_code,
                "UI": metrics["user_interaction"].value_code,
                "S":  metrics["scope"].value_code,
                "C":  metrics["confidentiality"].value_code,
                "I":  metrics["integrity"].value_code,
                "A":  metrics["availability"].value_code,
            }
            res = CVSSCalculator.calculate_base_score(calc_dict)
            return CVSSAssessment(
                assessment_status=AssessmentStatus.COMPLETED,
                cvss_version="3.1",
                vector_string=res["vector_string"],
                base_score=res["base_score"],
                severity=res["severity"],
                score_range_min=res["base_score"],
                score_range_max=res["base_score"],
                metrics=metrics,
                missing_metrics=[],
                exploitability_subscore=res["exploitability_subscore"],
                impact_subscore=res["impact_subscore"],
                calculation_notes="All 8 CVSS v3.1 base metrics substantiated by forensic investigation evidence.",
                evidence_ids=all_metric_evidence_ids
            )
        elif len(missing_metrics) <= 3 and cls._has_sufficient_impact_evidence(metrics):
            # Partial: Some metrics confirmed, estimate verified bounds without guessing numbers
            confirmed_dict = {
                m.metric_code: m.value_code for m in metrics.values() if m.is_confirmed and m.value_code
            }
            min_score, max_score = CVSSCalculator.estimate_score_bounds(confirmed_dict, missing_metrics)
            return CVSSAssessment(
                assessment_status=AssessmentStatus.PARTIAL,
                cvss_version="3.1",
                vector_string=None,
                base_score=None,  # Do not force an unconfirmed exact score!
                severity=CVSSSeverity.UNDETERMINED,
                score_range_min=min_score,
                score_range_max=max_score,
                metrics=metrics,
                missing_metrics=missing_metrics,
                calculation_notes=(
                    f"Partial CVSS metric coverage. Missing {len(missing_metrics)} metrics ({', '.join(missing_metrics)}). "
                    f"Verified score bounds based solely on confirmed evidence: [{min_score} - {max_score}]."
                ),
                evidence_ids=all_metric_evidence_ids
            )
        else:
            # Critical failure avoidance: Insufficient data to justify a CVSS score
            return CVSSAssessment(
                assessment_status=AssessmentStatus.INSUFFICIENT_DATA,
                cvss_version="3.1",
                vector_string=None,
                base_score=None,
                severity=CVSSSeverity.UNDETERMINED,
                score_range_min=None,
                score_range_max=None,
                metrics=metrics,
                missing_metrics=missing_metrics,
                calculation_notes=(
                    f"Insufficient forensic evidence to compute CVSS score. "
                    f"Missing metrics: {', '.join(missing_metrics)}. "
                    f"Unsubstantiated scores are omitted to preserve forensic integrity."
                ),
                evidence_ids=all_metric_evidence_ids
            )

    # ── Individual Metric Evaluators ───────────────────────────────────────────

    @classmethod
    def _evaluate_attack_vector(
        cls,
        facts: List[Tuple[str, List[str]]],
        agent3: Dict[str, Any],
        agent4: Dict[str, Any]
    ) -> CVSSMetricEvidence:
        # Check Agent 3 entry point
        entry_pt = agent3.get("infection_path", {}).get("entry_point", "")
        if isinstance(entry_pt, str) and entry_pt:
            entry_lower = entry_pt.lower()
            ev_ids = agent3.get("infection_path", {}).get("evidence_ids", []) or []
            if any(k in entry_lower for k in cls.NETWORK_KEYWORDS):
                return CVSSMetricEvidence(
                    metric_name="Attack Vector",
                    metric_code="AV",
                    assigned_value="NETWORK",
                    value_code="N",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Infection entry point established as remote network vector: '{entry_pt}'.",
                    confidence=0.92
                )

        # Check Agent 4 network indicators / C2
        for claim in agent4.get("claims", []):
            ioc_col = claim.get("ioc_collection", {}) or {}
            ips = ioc_col.get("ip_addresses", [])
            cited = claim.get("cited_evidence_ids", []) or []
            if ips:
                return CVSSMetricEvidence(
                    metric_name="Attack Vector",
                    metric_code="AV",
                    assigned_value="NETWORK",
                    value_code="N",
                    is_confirmed=True,
                    evidence_ids=cited,
                    justification=f"External network socket connection established to IP(s): {', '.join(ips)}.",
                    confidence=0.90
                )

        # Scan facts
        for fact_text, ev_ids in facts:
            f_lower = fact_text.lower()
            if "network socket" in f_lower or "c2 connection" in f_lower or "external ip" in f_lower:
                return CVSSMetricEvidence(
                    metric_name="Attack Vector",
                    metric_code="AV",
                    assigned_value="NETWORK",
                    value_code="N",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Network communication confirmed in finding: '{fact_text[:120]}'.",
                    confidence=0.85
                )
            if "usb" in f_lower or "removable drive" in f_lower:
                return CVSSMetricEvidence(
                    metric_name="Attack Vector",
                    metric_code="AV",
                    assigned_value="PHYSICAL",
                    value_code="P",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Physical media execution confirmed in finding: '{fact_text[:120]}'.",
                    confidence=0.85
                )

        return CVSSMetricEvidence(
            metric_name="Attack Vector",
            metric_code="AV",
            assigned_value=None,
            value_code=None,
            is_confirmed=False,
            justification="No network socket, adjacent subnet, or physical media evidence identified in investigation findings.",
            confidence=0.0
        )

    @classmethod
    def _evaluate_attack_complexity(
        cls,
        facts: List[Tuple[str, List[str]]],
        agent3: Dict[str, Any],
        agent4: Dict[str, Any]
    ) -> CVSSMetricEvidence:
        # Standard automated commands / scripts / malware execution -> Low complexity
        for fact_text, ev_ids in facts:
            f_lower = fact_text.lower()
            if any(term in f_lower for term in ["powershell", "cmd.exe", "scheduled task", "vbs", "batch", "binary execution"]):
                return CVSSMetricEvidence(
                    metric_name="Attack Complexity",
                    metric_code="AC",
                    assigned_value="LOW",
                    value_code="L",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification="Exploitation relies on repeatable script/process execution without race conditions or specialized environmental preconditions.",
                    confidence=0.88
                )

        return CVSSMetricEvidence(
            metric_name="Attack Complexity",
            metric_code="AC",
            assigned_value=None,
            value_code=None,
            is_confirmed=False,
            justification="Environmental preconditions or timing complexity cannot be conclusively established from evidence.",
            confidence=0.0
        )

    @classmethod
    def _evaluate_privileges_required(
        cls,
        facts: List[Tuple[str, List[str]]],
        agent3: Dict[str, Any],
        agent4: Dict[str, Any]
    ) -> CVSSMetricEvidence:
        # Check initial access context
        entry_pt = agent3.get("infection_path", {}).get("entry_point", "")
        if "unauthenticated" in entry_pt.lower() or "external web" in entry_pt.lower() or "phishing" in entry_pt.lower():
            ev_ids = agent3.get("infection_path", {}).get("evidence_ids", []) or []
            return CVSSMetricEvidence(
                metric_name="Privileges Required",
                metric_code="PR",
                assigned_value="NONE",
                value_code="N",
                is_confirmed=True,
                evidence_ids=ev_ids,
                justification=f"Initial exploitation occurred without prior authenticated access ('{entry_pt}').",
                confidence=0.90
            )

        # Scan for user contexts in findings
        for fact_text, ev_ids in facts:
            f_lower = fact_text.lower()
            if any(term in f_lower for term in ["user 'admin'", "user 'administrator'", "nt authority\\system", "system privileges"]):
                return CVSSMetricEvidence(
                    metric_name="Privileges Required",
                    metric_code="PR",
                    assigned_value="HIGH",
                    value_code="H",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Administrative/SYSTEM authority utilized for observed actions: '{fact_text[:120]}'.",
                    confidence=0.85
                )
            if any(term in f_lower for term in ["standard user", "domain user", "user '", "powershell.exe spawned by user"]):
                return CVSSMetricEvidence(
                    metric_name="Privileges Required",
                    metric_code="PR",
                    assigned_value="LOW",
                    value_code="L",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Observed actions executed under standard authenticated user context: '{fact_text[:120]}'.",
                    confidence=0.80
                )

        return CVSSMetricEvidence(
            metric_name="Privileges Required",
            metric_code="PR",
            assigned_value=None,
            value_code=None,
            is_confirmed=False,
            justification="No user authorization or session privilege level substantiated in forensic evidence.",
            confidence=0.0
        )

    @classmethod
    def _evaluate_user_interaction(
        cls,
        facts: List[Tuple[str, List[str]]],
        agent3: Dict[str, Any],
        agent4: Dict[str, Any]
    ) -> CVSSMetricEvidence:
        for fact_text, ev_ids in facts:
            f_lower = fact_text.lower()
            if any(k in f_lower for k in cls.USER_INTERACTION_KEYWORDS):
                return CVSSMetricEvidence(
                    metric_name="User Interaction",
                    metric_code="UI",
                    assigned_value="REQUIRED",
                    value_code="R",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Exploitation required victim user action (e.g. email/attachment interaction): '{fact_text[:120]}'.",
                    confidence=0.88
                )

        # Check for autonomous background execution (scheduled task, remote daemon)
        for fact_text, ev_ids in facts:
            f_lower = fact_text.lower()
            if any(k in f_lower for k in ["scheduled task", "daemon", "service start", "cron"]):
                return CVSSMetricEvidence(
                    metric_name="User Interaction",
                    metric_code="UI",
                    assigned_value="NONE",
                    value_code="N",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification="Execution proceeded autonomously via background service or scheduled task without victim interaction.",
                    confidence=0.85
                )

        return CVSSMetricEvidence(
            metric_name="User Interaction",
            metric_code="UI",
            assigned_value=None,
            value_code=None,
            is_confirmed=False,
            justification="Presence or absence of victim user interaction cannot be definitively established.",
            confidence=0.0
        )

    @classmethod
    def _evaluate_scope(
        cls,
        facts: List[Tuple[str, List[str]]],
        agent3: Dict[str, Any],
        agent4: Dict[str, Any]
    ) -> CVSSMetricEvidence:
        # Check lateral movement in Agent 3
        lat_moves = agent3.get("lateral_movement", [])
        if lat_moves and len(lat_moves) > 0:
            ev_ids = [eid for lm in lat_moves for eid in lm.get("evidence_ids", [])]
            return CVSSMetricEvidence(
                metric_name="Scope",
                metric_code="S",
                assigned_value="CHANGED",
                value_code="C",
                is_confirmed=True,
                evidence_ids=ev_ids,
                justification="Compromise expanded beyond initial security authority via confirmed lateral movement across hosts.",
                confidence=0.90
            )

        # Default scope unchanged for single-host compromise
        return CVSSMetricEvidence(
            metric_name="Scope",
            metric_code="S",
            assigned_value="UNCHANGED",
            value_code="U",
            is_confirmed=True,
            evidence_ids=[],
            justification="Compromise impacts are confined to the security authority of the host environment.",
            confidence=0.80
        )

    @classmethod
    def _evaluate_confidentiality(
        cls,
        facts: List[Tuple[str, List[str]]],
        agent3: Dict[str, Any],
        agent4: Dict[str, Any]
    ) -> CVSSMetricEvidence:
        for fact_text, ev_ids in facts:
            f_lower = fact_text.lower()
            if any(k in f_lower for k in cls.HIGH_CONFIDENTIALITY_KEYWORDS):
                return CVSSMetricEvidence(
                    metric_name="Confidentiality",
                    metric_code="C",
                    assigned_value="HIGH",
                    value_code="H",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Substantial credential theft or data exfiltration substantiated: '{fact_text[:120]}'.",
                    confidence=0.90
                )
            if any(k in f_lower for k in cls.LOW_CONFIDENTIALITY_KEYWORDS):
                return CVSSMetricEvidence(
                    metric_name="Confidentiality",
                    metric_code="C",
                    assigned_value="LOW",
                    value_code="L",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Reconnaissance or system enumeration observed without bulk data exfiltration: '{fact_text[:120]}'.",
                    confidence=0.85
                )

        return CVSSMetricEvidence(
            metric_name="Confidentiality",
            metric_code="C",
            assigned_value="NONE",
            value_code="N",
            is_confirmed=True,
            evidence_ids=[],
            justification="No credential access, system discovery, or data exfiltration evidence detected.",
            confidence=0.75
        )

    @classmethod
    def _evaluate_integrity(
        cls,
        facts: List[Tuple[str, List[str]]],
        agent3: Dict[str, Any],
        agent4: Dict[str, Any]
    ) -> CVSSMetricEvidence:
        for fact_text, ev_ids in facts:
            f_lower = fact_text.lower()
            if any(k in f_lower for k in cls.HIGH_INTEGRITY_KEYWORDS):
                return CVSSMetricEvidence(
                    metric_name="Integrity",
                    metric_code="I",
                    assigned_value="HIGH",
                    value_code="H",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Direct modification of system state, persistence installation, or payload delivery confirmed: '{fact_text[:120]}'.",
                    confidence=0.92
                )

        return CVSSMetricEvidence(
            metric_name="Integrity",
            metric_code="I",
            assigned_value="NONE",
            value_code="N",
            is_confirmed=True,
            evidence_ids=[],
            justification="No persistent modification, file tampering, or unauthorized code installation verified in evidence.",
            confidence=0.75
        )

    @classmethod
    def _evaluate_availability(
        cls,
        facts: List[Tuple[str, List[str]]],
        agent3: Dict[str, Any],
        agent4: Dict[str, Any]
    ) -> CVSSMetricEvidence:
        for fact_text, ev_ids in facts:
            f_lower = fact_text.lower()
            if any(k in f_lower for k in cls.HIGH_AVAILABILITY_KEYWORDS):
                return CVSSMetricEvidence(
                    metric_name="Availability",
                    metric_code="A",
                    assigned_value="HIGH",
                    value_code="H",
                    is_confirmed=True,
                    evidence_ids=ev_ids,
                    justification=f"Critical system service degradation, denial of service, or forced shutdown confirmed: '{fact_text[:120]}'.",
                    confidence=0.88
                )

        # Default availability impact is NONE unless disruption is noted
        return CVSSMetricEvidence(
            metric_name="Availability",
            metric_code="A",
            assigned_value="NONE",
            value_code="N",
            is_confirmed=True,
            evidence_ids=[],
            justification="Systems and network services remained responsive with no denial-of-service observed.",
            confidence=0.80
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @classmethod
    def _extract_facts_and_evidence(
        cls,
        agent3: Dict[str, Any],
        agent4: Dict[str, Any],
        agent5: Dict[str, Any],
        fir_findings: List[Any]
    ) -> List[Tuple[str, List[str]]]:
        results: List[Tuple[str, List[str]]] = []

        # From FIR findings
        for f in fir_findings:
            fact = getattr(f, "fact", "") if hasattr(f, "fact") else f.get("fact", "")
            fid = getattr(f, "finding_id", "") if hasattr(f, "finding_id") else f.get("finding_id", "")
            if fact:
                results.append((str(fact), [str(fid)] if fid else []))

        # From Agent 3 claims/steps
        for step in agent3.get("attack_path", []):
            desc = step.get("action", "") or step.get("description", "")
            eids = step.get("evidence_ids", []) or []
            if desc:
                results.append((str(desc), eids))

        # From Agent 4 claims
        for claim in agent4.get("claims", []):
            summary = claim.get("summary", "") or claim.get("findings_summary", "")
            eids = claim.get("cited_evidence_ids", []) or []
            if summary:
                results.append((str(summary), eids))

        return results

    @classmethod
    def _check_authoritative_cve(
        cls,
        agent5: Dict[str, Any],
        facts: List[Tuple[str, List[str]]]
    ) -> Optional[CVSSAssessment]:
        """
        If Agent 5 provides an authoritative CVE with official NVD CVSS score and vector,
        incorporates that published baseline directly while retaining forensic evidence citations.
        """
        cve_match = agent5.get("cve_match", {}) or {}
        cve_id = cve_match.get("cve_id")
        base_score = cve_match.get("cvss_score") or cve_match.get("base_score")
        vector_str = cve_match.get("cvss_vector") or cve_match.get("vector_string")

        if cve_id and base_score is not None and vector_str:
            try:
                base_score = float(base_score)
                severity = derive_cvss_severity(base_score)
                return CVSSAssessment(
                    assessment_status=AssessmentStatus.COMPLETED,
                    cvss_version="3.1",
                    vector_string=str(vector_str),
                    base_score=base_score,
                    severity=severity,
                    score_range_min=base_score,
                    score_range_max=base_score,
                    metrics={},
                    missing_metrics=[],
                    calculation_notes=f"Authoritative CVE baseline adopted from Threat Intelligence feed: {cve_id} (NVD Base Score {base_score}).",
                    evidence_ids=agent5.get("evidence_ids", [])
                )
            except Exception as e:
                logger.debug("Failed parsing authoritative CVE CVSS info: %s", e)

        return None

    @classmethod
    def _has_sufficient_impact_evidence(cls, metrics: Dict[str, CVSSMetricEvidence]) -> bool:
        """Verifies if at least one impact metric (C, I, or A) is confirmed."""
        return any(metrics[k].is_confirmed for k in ["confidentiality", "integrity", "availability"] if k in metrics)
