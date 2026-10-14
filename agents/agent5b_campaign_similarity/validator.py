"""
Agent 5b — Output & Evidence Reference Validator
================================================
Enforces:
1. Evidence Reference Validation: Cites only authorized evidence IDs belonging to current case.
2. Strict Non-Override Rule: Historical similarity cannot overwrite or contradict current evidence.
3. Score bounds validation [0.0, 1.0] and numerical sanitization against NaN/inf.
4. Adds mandatory analytical limitations and attribution safeguards.
"""

from typing import List, Set, Optional, Any
import math
import logging
from agents.agent5b_campaign_similarity.schemas import (
    Agent5bOutput,
    HistoricalSimilarityOutput
)

logger = logging.getLogger(__name__)


class Agent5bValidator:
    """
    Validates Agent 5b outputs and sanitizes evidence citations.
    """

    MANDATORY_LIMITATIONS = [
        "Historical cases are contextual references only, never proof of identity or attribution.",
        "Historical similarity cannot override or contradict current forensic evidence.",
        "Missing evidence in current investigation must not be interpreted as confirmed proof of absence.",
        "Similarity scoring reflects semantic proximity in behavior and kill-chain alignment, not investigative certainty.",
        "Investigative confidence is an empirical forensic-coverage score, not a calibrated statistical probability."
    ]

    ATTRIBUTION_SAFEGUARDS = [
        "Historical case similarity is contextual reference only, never proof of identity or attribution.",
        "Malware family associations reflect behavioral resemblance only, not confirmed family identity.",
        "Campaign correlations reflect overlapping techniques and infrastructure; do not assert campaign membership.",
        "Threat actor context provides profiling background; does not assert that the actor conducted the current attack.",
        "Previous cases never override current forensic evidence."
    ]

    @classmethod
    def validate_and_refine(
        cls,
        output: Agent5bOutput,
        valid_evidence_ids: Optional[Set[str]] = None
    ) -> Agent5bOutput:
        """
        Validates output fields, purges invalid evidence references, and clamps scores.
        """
        valid_eids = valid_evidence_ids or set()
        hs = output.historical_similarity

        # 1. Clamp and sanitize scores
        hs.behavior_similarity = cls._clamp(hs.behavior_similarity)
        hs.attack_similarity = cls._clamp(hs.attack_similarity)
        hs.intelligence_similarity = cls._clamp(hs.intelligence_similarity)
        hs.composite_similarity = cls._clamp(hs.composite_similarity)
        hs.confidence = cls._clamp(hs.confidence)

        if hs.similarity_breakdown:
            hs.similarity_breakdown.behavior_similarity = cls._clamp(hs.similarity_breakdown.behavior_similarity)
            hs.similarity_breakdown.attack_similarity = cls._clamp(hs.similarity_breakdown.attack_similarity)
            hs.similarity_breakdown.intelligence_similarity = cls._clamp(hs.similarity_breakdown.intelligence_similarity)
            hs.similarity_breakdown.composite_similarity = cls._clamp(hs.similarity_breakdown.composite_similarity)

        # 2. Validate evidence references
        if valid_eids:
            clean_eids = [eid for eid in output.evidence_ids if eid in valid_eids]
            purged = set(output.evidence_ids) - set(clean_eids)
            if purged:
                logger.warning(f"Purged invalid/unauthorized evidence IDs from Agent 5b output: {purged}")
                output.validation_warnings.append(
                    f"Purged {len(purged)} invalid/unauthorized evidence reference(s): {sorted(list(purged))}"
                )
            output.evidence_ids = clean_eids

            # Also filter supporting evidence in novelty and different_behaviors
            hs.novelty.supporting_evidence_references = [
                eid for eid in hs.novelty.supporting_evidence_references if eid in valid_eids
            ]
            for diff in hs.different_behaviors:
                diff.supporting_evidence_ids = [
                    eid for eid in diff.supporting_evidence_ids if eid in valid_eids
                ]

        # 3. Ensure mandatory limitations are present
        for lim in cls.MANDATORY_LIMITATIONS:
            if lim not in hs.limitations:
                hs.limitations.append(lim)

        # 4. Check for unverified historical override in claim text
        output.claim = cls._sanitize_claim_overrides(output.claim)

        # 5. Populate or refine Agent 6 handoff
        if output.agent6_handoff:
            output.agent6_handoff.limitations = list(hs.limitations)
            output.agent6_handoff.attribution_safeguards = list(cls.ATTRIBUTION_SAFEGUARDS)
            output.agent6_handoff.supporting_evidence_references = list(output.evidence_ids)
            output.agent6_handoff.investigative_confidence = hs.confidence
            output.agent6_handoff.confidence_methodology = hs.confidence_methodology
            if valid_eids and "different_behaviors" in output.agent6_handoff.behavior_comparisons:
                for db in output.agent6_handoff.behavior_comparisons["different_behaviors"]:
                    if isinstance(db, dict) and "supporting_evidence_ids" in db:
                        db["supporting_evidence_ids"] = [
                            eid for eid in db["supporting_evidence_ids"] if eid in valid_eids
                        ]

        return output

    @staticmethod
    def _clamp(val: Any) -> float:
        if val is None:
            return 0.0
        try:
            f = float(val)
            if math.isnan(f) or math.isinf(f):
                return 0.0
            return max(0.0, min(1.0, f))
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def _sanitize_claim_overrides(claim: str) -> str:
        """
        Ensures claims do not assert definitive proof based on historical similarity.
        """
        bad_phrases = [
            ("proves that this is", "suggests behavioral similarity to"),
            ("confirms that this case is", "exhibits similarity to"),
            ("is definitively", "is contextually similar to"),
            ("proves that the attacker is", "exhibits characteristics associated with")
        ]
        res = claim
        for bad, repl in bad_phrases:
            if bad in res.lower():
                # Case-insensitive replacement
                idx = res.lower().find(bad)
                while idx != -1:
                    res = res[:idx] + repl + res[idx + len(bad):]
                    idx = res.lower().find(bad)
        return res
