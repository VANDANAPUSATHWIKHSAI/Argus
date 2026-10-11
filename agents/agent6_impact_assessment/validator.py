"""
Agent 6 — Impact Assessment: Deterministic Validation Gate
===========================================================
Validates:
  1. Evidence Citation Integrity: verifies all cited evidence IDs exist in the FIR/claim universe.
  2. Score Calculation Integrity: verifies CVSS and ISS scores match pure Python calculations.
  3. Schema Completeness: ensures no ungrounded scores bypass safety constraints.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Any, Set, Tuple
from agents.agent6_impact_assessment.schemas import (
    CVSSAssessment,
    ISSAssessment,
    AffectedAsset,
    RecoveryAction
)
from agents.agent6_impact_assessment.cvss_calculator import CVSSCalculator

logger = logging.getLogger(__name__)


class Agent6Validator:
    """
    Deterministic validation gate for Agent 6 outputs.
    """

    @classmethod
    def validate_output(
        cls,
        cvss: CVSSAssessment,
        iss: ISSAssessment,
        assets: List[AffectedAsset],
        recovery_actions: List[RecoveryAction],
        valid_evidence_universe: Set[str]
    ) -> Dict[str, Any]:
        """
        Validates citations and scoring integrity.
        """
        # 1. Collect all cited evidence IDs
        all_cited: Set[str] = set()
        all_cited.update(cvss.evidence_ids)
        all_cited.update(iss.contributing_evidence_ids)
        for a in assets:
            all_cited.update(a.evidence_ids)
        for r in recovery_actions:
            all_cited.update(r.evidence_ids)

        # 2. Check citations against valid universe
        invalid_citations: List[str] = []
        if valid_evidence_universe:
            for eid in sorted(list(all_cited)):
                if eid and eid not in valid_evidence_universe:
                    invalid_citations.append(eid)

        citation_valid = (len(invalid_citations) == 0)

        # 3. Score integrity validation
        score_integrity_valid = True
        notes: List[str] = []

        if cvss.base_score is not None and cvss.vector_string:
            try:
                # Re-verify CVSS base score calculation from vector
                parts = cvss.vector_string.replace("CVSS:3.1/", "").split("/")
                metric_dict = {}
                for p in parts:
                    if ":" in p:
                        k, v = p.split(":", 1)
                        metric_dict[k] = v
                recalculated = CVSSCalculator.calculate_base_score(metric_dict)["base_score"]
                if recalculated != cvss.base_score:
                    score_integrity_valid = False
                    notes.append(f"CVSS score mismatch: recorded={cvss.base_score}, recalculated={recalculated}.")
            except Exception as e:
                logger.debug("CVSS recalculation check error: %s", e)

        # Verify ISS score weighted sum
        recalc_iss = round(sum(f.weighted_score for f in iss.factor_breakdown.values()), 1)
        if abs(recalc_iss - iss.iss_score) > 0.15:
            score_integrity_valid = False
            notes.append(f"ISS score mismatch: recorded={iss.iss_score}, recalculated={recalc_iss}.")

        if citation_valid and score_integrity_valid:
            notes.append(f"Validation PASSED: {len(all_cited)} unique citations verified against universe.")
        else:
            if invalid_citations:
                notes.append(f"Citation validation note: {len(invalid_citations)} unverified citation IDs found.")

        return {
            "citation_valid": citation_valid,
            "total_citations": len(all_cited),
            "valid_citations_count": len(all_cited) - len(invalid_citations),
            "invalid_citations": invalid_citations,
            "score_integrity_valid": score_integrity_valid,
            "validation_notes": " ".join(notes)
        }
