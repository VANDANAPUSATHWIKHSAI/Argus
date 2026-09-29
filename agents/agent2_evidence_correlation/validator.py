"""
Agent 2 — Deterministic Validation Gate
==========================================
Verifies that claims produced by Agent 2 strictly cite valid FIR finding IDs
and carry valid confidence scores.
"""

import logging
from typing import List, Set, Tuple, Any
from agents.agent2_evidence_correlation.schemas import Agent2Claim

logger = logging.getLogger(__name__)


class Agent2Validator:
    """
    Deterministic validation gate for Agent 2 evidence correlation claims.
    """

    def extract_valid_id_universe(self, findings: List[Any]) -> Tuple[Set[str], Set[str]]:
        """
        Extracts valid finding IDs and evidence reference lineage IDs from input findings.
        Returns: (set_of_finding_ids, set_of_lineage_ids)
        """
        valid_finding_ids: Set[str] = set()
        valid_lineage_ids: Set[str] = set()

        for finding in findings:
            fid = None
            ev_refs = []

            if isinstance(finding, dict):
                fid = finding.get("finding_id") or finding.get("id")
                ev_refs = finding.get("evidence_reference") or finding.get("cited_evidence_ids") or []
            elif hasattr(finding, "finding_id"):
                fid = getattr(finding, "finding_id")
                ev_refs = getattr(finding, "evidence_reference", [])
            elif hasattr(finding, "id"):
                fid = getattr(finding, "id")
                ev_refs = getattr(finding, "evidence_reference", [])

            if fid:
                valid_finding_ids.add(str(fid).strip())

            if isinstance(ev_refs, str):
                ev_refs = [x.strip() for x in ev_refs.split(",") if x.strip()]
            if isinstance(ev_refs, list):
                for ref in ev_refs:
                    if ref:
                        valid_lineage_ids.add(str(ref).strip())

        return valid_finding_ids, valid_lineage_ids

    def validate_claims(
        self,
        claims: List[Agent2Claim],
        valid_finding_ids: Set[str],
        valid_lineage_ids: Set[str]
    ) -> List[Agent2Claim]:
        """
        Validates citations and confidence scores for a list of Agent2Claim objects.
        Returns the updated list with verification flags set.
        """
        validated_claims: List[Agent2Claim] = []
        universe = valid_finding_ids.union(valid_lineage_ids)

        for claim in claims:
            cited = claim.cited_evidence_ids or []
            invalid_citations: List[str] = []

            for cid in cited:
                cid_clean = str(cid).strip()
                if cid_clean not in universe:
                    invalid_citations.append(cid_clean)

            if invalid_citations:
                claim.citation_verified = False
                claim.invalid_citations = invalid_citations
                logger.warning(
                    "Agent 2 Validator: Claim %s cited invalid finding IDs: %s",
                    claim.claim_id, invalid_citations
                )
            elif cited:
                claim.citation_verified = True
                claim.invalid_citations = []
            else:
                # No citations provided
                claim.citation_verified = False
                claim.invalid_citations = []

            # Confidence score validation
            raw_conf = claim.confidence_score
            if raw_conf < 0.0 or raw_conf > 1.0:
                claim.is_valid_confidence = False
                claim.raw_model_confidence = raw_conf
                # Clamp confidence into [0.0, 1.0] range
                if raw_conf > 1.0 and raw_conf <= 100.0:
                    claim.confidence_score = round(raw_conf / 100.0, 2)
                else:
                    claim.confidence_score = max(0.0, min(1.0, raw_conf))
                logger.warning(
                    "Agent 2 Validator: Claim %s confidence %s clamped to %s",
                    claim.claim_id, raw_conf, claim.confidence_score
                )
            else:
                claim.is_valid_confidence = True

            notes = []
            if claim.citation_verified:
                notes.append("Citations verified against FIR universe.")
            else:
                if invalid_citations:
                    notes.append(f"Invalid citations detected: {invalid_citations}.")
                else:
                    notes.append("No citations provided for claim.")

            if not claim.is_valid_confidence:
                notes.append(f"Confidence score {raw_conf} was out of bounds and clamped.")

            claim.validation_notes = " ".join(notes)
            validated_claims.append(claim)

        return validated_claims
