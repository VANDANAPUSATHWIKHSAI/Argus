"""
Agent 5b — Behavior Delta & Novelty Analyzer
============================================
Performs Common / New / Different / Historical-Only classification
and detects Knowledge Deltas / Novel Threat behaviors against historical cases.

Enforces:
- Strict mechanism differentiation (e.g. Registry Run Key vs Scheduled Task are DIFFERENT, not COMMON)
- Preserves supporting evidence IDs for every current-case behavior
- Distinguishes unobserved behavior from confirmed absence for historical_only
- Distinct novelty fields: historical_novelty, mitre_unmapped, novel_threat_candidate, confirmed_novel_threat
"""

from typing import List, Dict, Any, Set, Tuple, Optional
import re
import logging
from agents.agent5b_campaign_similarity.schemas import (
    CaseBehavioralSignature,
    RetrievedHistoricalCase,
    DifferentBehaviorDetail,
    NoveltyReport
)

logger = logging.getLogger(__name__)


class BehaviorDeltaAnalyzer:
    """
    Analyzes behavioral overlaps, differences, and novelty between
    the current investigation and retrieved historical cases.
    """

    CATEGORIES = [
        "execution", "persistence", "credential_access", "privilege_escalation",
        "defense_evasion", "discovery", "collection", "command_and_control",
        "exfiltration", "impact"
    ]

    # Specific distinct mechanism tokens that preclude "COMMON" matching
    # Even if they share words, these are fundamentally different mechanisms
    INCOMPATIBLE_MECHANISMS = [
        ("registry run", "scheduled task"),
        ("registry run", "schtasks"),
        ("run key", "scheduled task"),
        ("run key", "task scheduler"),
        ("runonce", "scheduled task"),
        ("startup folder", "registry"),
        ("startup folder", "scheduled task"),
        ("browser", "lsass"),
        ("browser credential", "sam"),
        ("browser credential", "ntds"),
        ("powershell", "wmi"),
        ("powershell", "cmd.exe"),
        ("wmi", "cmd.exe"),
        ("dns", "https"),
        ("dns", "cloud-storage"),
        ("https", "cloud-storage"),
        ("https", "rclone"),
        ("mega.nz", "dropbox"),
        ("raw disk", "vssadmin"),
        ("wiper", "ransomware")
    ]

    @classmethod
    def analyze(
        cls,
        current_sig: CaseBehavioralSignature,
        retrieved_cases: List[RetrievedHistoricalCase]
    ) -> Tuple[List[str], List[str], List[DifferentBehaviorDetail], List[str], NoveltyReport]:
        """
        Returns:
        (common_behaviors, new_behaviors, different_behaviors, historical_only_behaviors, novelty_report)
        """
        current_by_cat = cls._extract_current_behaviors_by_cat(current_sig)
        evidence_map = current_sig.malware_behavior.behavior_evidence_map

        all_current_behaviors: Set[str] = set()
        for items in current_by_cat.values():
            all_current_behaviors.update(items)

        # Cases compared
        cases_compared = [c.case_id for c in retrieved_cases]

        # MITRE unmapped behaviors
        mitre_techs = set(current_sig.threat_intelligence.mitre_techniques)
        mitre_unmapped: List[str] = []
        for b in sorted(list(all_current_behaviors)):
            # If behavior doesn't contain a MITRE technique ID (e.g. T1059) and no techniques in TI
            has_mitre_tag = bool(re.search(r'\bT1\d{3}(\.\d{3})?\b', b))
            if not has_mitre_tag and not mitre_techs:
                mitre_unmapped.append(b)

        if not retrieved_cases:
            new_list = sorted(list(all_current_behaviors))
            novelty = NoveltyReport(
                detected=bool(new_list),
                observations=[
                    f"No matching validated historical cases found. All {len(new_list)} observed behaviors are unrepresented."
                ] if new_list else ["No historical cases retrieved; no observed behaviors."],
                novelty_score=1.0 if new_list else 0.0,
                novel_mechanisms=new_list,
                historical_novelty=new_list,
                mitre_unmapped=mitre_unmapped,
                novel_threat_candidate=bool(new_list),
                novel_threat_candidate_reason=(
                    "No historical investigations match current observations; candidate for novel threat review."
                    if new_list else ""
                ),
                confirmed_novel_threat=False,  # Strict safeguard: never auto-confirmed solely due to 0 matches
                confirmation_rationale="Absence of historical matches establishes candidate status only. Formal confirmation requires authorized validation workflow.",
                historical_cases_compared=[],
                supporting_evidence_references=current_sig.evidence_ids
            )
            return [], new_list, [], [], novelty

        top_case = retrieved_cases[0]
        top_hist_by_cat = cls._extract_historical_behaviors_by_cat(top_case)

        union_hist_behaviors: Set[str] = set()
        for case in retrieved_cases:
            h_cat = cls._extract_historical_behaviors_by_cat(case)
            for items in h_cat.values():
                union_hist_behaviors.update(items)

        common: Set[str] = set()
        new_beh: Set[str] = set()
        different: List[DifferentBehaviorDetail] = []
        hist_only: Set[str] = set()

        for cat in cls.CATEGORIES:
            curr_set = current_by_cat.get(cat, set())
            hist_set = top_hist_by_cat.get(cat, set())

            cat_common = set()
            for cb in curr_set:
                matched = False
                for hb in hist_set:
                    if cls._is_match(cb, hb):
                        cat_common.add(cb)
                        matched = True
                        break
                if not matched:
                    # Check union across all retrieved cases
                    in_any = any(cls._is_match(cb, ub) for ub in union_hist_behaviors)
                    if in_any:
                        cat_common.add(cb)
                    else:
                        new_beh.add(cb)

            common.update(cat_common)

            # Different Behaviors: same category, different mechanism
            unmatched_curr = curr_set - cat_common
            unmatched_hist = set()
            for hb in hist_set:
                if not any(cls._is_match(cb, hb) for cb in cat_common):
                    unmatched_hist.add(hb)

            if unmatched_curr and unmatched_hist:
                for uc in sorted(list(unmatched_curr)):
                    for uh in sorted(list(unmatched_hist)):
                        eids = evidence_map.get(uc, current_sig.evidence_ids)
                        diff_reason = (
                            f"Category '{cat}': Current case uses '{uc}' whereas historical "
                            f"Case '{top_case.case_id}' used '{uh}'. These are distinct mechanisms."
                        )
                        different.append(DifferentBehaviorDetail(
                            category=cat,
                            current_behavior=uc,
                            historical_behavior=uh,
                            difference_reason=diff_reason,
                            supporting_evidence_ids=eids
                        ))

            # Historical Only: observed in historical case, NOT in current case
            for hb in hist_set:
                if not any(cls._is_match(cb, hb) for cb in curr_set):
                    hist_only.add(
                        f"{cat}: {hb} [Recorded in Case {top_case.case_id}; unobserved in current evidence. Unobserved does not prove absence.]"
                    )

        # 2. Novelty and Knowledge-Delta Synthesis
        novel_mechs = sorted(list(new_beh))
        novelty_obs: List[str] = []
        if novel_mechs:
            for nb in novel_mechs:
                novelty_obs.append(
                    f"Behavior '{nb}' is not represented in any of the {len(retrieved_cases)} retrieved historical cases ({', '.join(cases_compared)})."
                )

        total_curr = len(all_current_behaviors)
        novelty_score = (len(new_beh) / total_curr) if total_curr > 0 else 0.0

        is_novel_candidate = bool(novel_mechs or (novelty_score > 0.40))
        candidate_reason = (
            f"Observed {len(novel_mechs)} behavior(s) unrepresented in historical validated investigations: {', '.join(novel_mechs[:3])}."
            if is_novel_candidate else "All observed behaviors have precedents in retrieved validated cases."
        )

        novelty_report = NoveltyReport(
            detected=bool(new_beh),
            observations=novelty_obs,
            novelty_score=round(novelty_score, 4),
            novel_mechanisms=novel_mechs,
            historical_novelty=novel_mechs,
            mitre_unmapped=mitre_unmapped,
            novel_threat_candidate=is_novel_candidate,
            novel_threat_candidate_reason=candidate_reason,
            confirmed_novel_threat=False,  # Safeguard: never auto-confirmed
            confirmation_rationale="Absence of historical match establishes candidate novelty only. Confirmed novelty requires authorized analyst validation.",
            historical_cases_compared=cases_compared,
            supporting_evidence_references=current_sig.evidence_ids
        )

        return (
            sorted(list(common)),
            sorted(list(new_beh)),
            different,
            sorted(list(hist_only)),
            novelty_report
        )

    @classmethod
    def _extract_current_behaviors_by_cat(cls, sig: CaseBehavioralSignature) -> Dict[str, Set[str]]:
        res: Dict[str, Set[str]] = {}
        for cat in cls.CATEGORIES:
            items = getattr(sig.malware_behavior, cat, [])
            res[cat] = set(items)
        return res

    @classmethod
    def _extract_historical_behaviors_by_cat(cls, retrieved: RetrievedHistoricalCase) -> Dict[str, Set[str]]:
        res: Dict[str, Set[str]] = {}
        fp = retrieved.case_data.malware_behavior_fingerprint or {}
        for cat in cls.CATEGORIES:
            items = fp.get(cat, [])
            res[cat] = set(items)
        return res

    @classmethod
    def _is_match(cls, b1: str, b2: str) -> bool:
        """
        Normalized comparison between two behavior strings.
        Strictly rejects incompatible mechanisms (e.g. Registry Run Key vs Scheduled Task).
        """
        s1 = b1.lower().strip()
        s2 = b2.lower().strip()

        if s1 == s2:
            return True

        # Check for explicitly incompatible mechanisms
        for m1, m2 in cls.INCOMPATIBLE_MECHANISMS:
            if (m1 in s1 and m2 in s2) or (m2 in s1 and m1 in s2):
                return False

        # Substring / mechanism containment if not incompatible
        if s1 in s2 or s2 in s1:
            return True

        # Normalized alphanumeric tokens overlap
        t1 = set(re.findall(r'[a-zA-Z0-9]+', s1))
        t2 = set(re.findall(r'[a-zA-Z0-9]+', s2))
        overlap = t1 & t2
        if len(overlap) >= 2 and len(overlap) / max(len(t1), len(t2)) > 0.65:
            return True

        return False
