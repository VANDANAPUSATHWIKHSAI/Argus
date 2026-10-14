"""
Agent 5b — Historical Case Explanation Generator
=================================================
Produces grounded explanations and synthesis claims strictly upholding:
- "HISTORICAL CASES ARE REFERENCES, NOT PROOF"
- "Historical cases never override current evidence"
- Exact reuse of deterministic composite and component similarity scores
- Explicit details on matched features, divergent mechanisms, novelty reasons, supporting evidence, and limitations.
"""

from typing import List, Dict, Any, Optional
import logging
from agents.agent5b_campaign_similarity.schemas import (
    CaseBehavioralSignature,
    RetrievedHistoricalCase,
    DifferentBehaviorDetail,
    NoveltyReport,
    SimilarMalwareFamily,
    SimilarityBreakdown
)

logger = logging.getLogger(__name__)


class ExplanationGenerator:
    """
    Generates structured narrative explanations and synthesis claims.
    """

    @classmethod
    def generate_explanations(
        cls,
        current_sig: CaseBehavioralSignature,
        retrieved_cases: List[RetrievedHistoricalCase],
        common_behaviors: List[str],
        different_behaviors: List[DifferentBehaviorDetail],
        novelty: NoveltyReport,
        similar_families: List[SimilarMalwareFamily],
        similarity_breakdown: Optional[SimilarityBreakdown] = None
    ) -> List[str]:
        explanations: List[str] = []

        if not retrieved_cases:
            explanations.append(
                "No validated historical cases exceeded the retrieval threshold. "
                "Current forensic evidence stands independently without historical match."
            )
            if novelty.detected:
                explanations.append(
                    f"Novel threat observations: {len(novelty.novel_mechanisms)} behavior(s) "
                    f"({', '.join(novelty.novel_mechanisms[:5])}) are unrepresented historically. "
                    f"{novelty.confirmation_rationale}"
                )
            return explanations

        top = retrieved_cases[0]
        fam_name = top.case_data.malware_identity.family
        comp_score = similarity_breakdown.composite_similarity if similarity_breakdown else top.similarity_score

        # 1. Deterministic similarity score explanation
        if similarity_breakdown:
            explanations.append(
                f"Historical Similarity Scoring: Composite similarity is {comp_score:.4f} "
                f"(Behavior: {similarity_breakdown.behavior_similarity:.4f}, "
                f"Attack Pattern: {similarity_breakdown.attack_similarity:.4f}, "
                f"Threat Intel: {similarity_breakdown.intelligence_similarity:.4f}). "
                f"Formula: {similarity_breakdown.formula}."
            )
        else:
            explanations.append(
                f"The current investigation exhibits a composite similarity of {comp_score:.4f} "
                f"(Behavior: {top.behavior_similarity:.4f}, Attack Pattern: {top.attack_similarity:.4f}, "
                f"Threat Intel: {top.intelligence_similarity:.4f}) with validated Case '{top.case_id}' "
                f"(associated with {fam_name})."
            )

        # 2. Matched features with supporting evidence references
        if common_behaviors:
            eids_summary = sorted(list(set(current_sig.evidence_ids)))
            eids_text = f" (supported by current case evidence: {', '.join(eids_summary[:4])})" if eids_summary else ""
            explanations.append(
                f"Matched behaviors with historical Case '{top.case_id}': "
                f"{', '.join(common_behaviors[:6])}{eids_text}."
            )

        # 3. Behavioral differences & distinct mechanisms
        if different_behaviors:
            diff_summaries = [d.difference_reason for d in different_behaviors[:3]]
            explanations.append(
                f"Divergent mechanisms: {'; '.join(diff_summaries)}."
            )

        # 4. Novelty / Knowledge Delta
        if novelty.detected and novelty.novel_mechanisms:
            explanations.append(
                f"Knowledge-Delta / Novelty: {len(novelty.novel_mechanisms)} observed behavior(s) "
                f"({', '.join(novelty.novel_mechanisms[:4])}) do not appear in retrieved historical records. "
                f"Candidate status: {novelty.novel_threat_candidate}. "
                f"Confirmed novel status: {novelty.confirmed_novel_threat} ({novelty.confirmation_rationale})."
            )

        # 5. MITRE unmapped observations
        if novelty.mitre_unmapped:
            explanations.append(
                f"MITRE ATT&CK Unmapped: {len(novelty.mitre_unmapped)} behavior(s) "
                f"({', '.join(novelty.mitre_unmapped[:3])}) currently lack standardized ATT&CK mappings."
            )

        # 6. Strict Non-Proof Principle & Attribution Safeguard
        explanations.append(
            f"Principle reminder: Validated historical Case '{top.case_id}' provides investigative reference and context only. "
            f"It does NOT prove current malware identity, does NOT attribute the attack, and NEVER overrides current forensic evidence."
        )

        return explanations

    @classmethod
    def generate_claim(
        cls,
        case_id: str,
        retrieved_cases: List[RetrievedHistoricalCase],
        common_behaviors: List[str],
        similar_families: List[SimilarMalwareFamily],
        novelty: NoveltyReport,
        evidence_ids: List[str],
        composite_sim: float
    ) -> str:
        """
        Synthesizes concise claim for BaseAgent contract using the EXACT deterministic composite similarity value.
        """
        if not retrieved_cases:
            nov_text = f" Novelty detected across {len(novelty.novel_mechanisms)} behaviors." if novelty.detected else ""
            return (
                f"Investigation {case_id}: No matching validated historical investigations found in repository.{nov_text} "
                "Current forensic evidence stands independently."
            )

        top = retrieved_cases[0]
        fam = top.case_data.malware_identity.family
        fam_text = f" (associated with {fam})" if fam and fam.lower() != "unknown" else ""

        common_text = f", sharing common behaviors ({', '.join(common_behaviors[:3])})" if common_behaviors else ""
        nov_text = f" Novel mechanisms observed ({', '.join(novelty.novel_mechanisms[:2])})." if novelty.detected else ""

        claim = (
            f"Case {case_id} exhibits behavioral and campaign similarities (composite: {composite_sim:.4f}) "
            f"to validated historical Case {top.case_id}{fam_text}{common_text}.{nov_text} "
            f"Historical cases serve as investigative context and do not constitute proof of identity or attribution."
        )
        return claim
