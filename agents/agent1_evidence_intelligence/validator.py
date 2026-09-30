"""
Agent 1 — Evidence Intelligence Validator
==========================================
Deterministic validation logic for Agent 1. Enforces:
  1. Citation verification against FIR finding_ids and source evidence lineage.
  2. Confidence range validation (rejects invalid values, preserving raw model output).
  3. Structured schema completeness.
"""

import logging
from typing import List, Set, Tuple, Any, Dict, Optional
from fir.schemas import FIRFinding
from sanitization.gateway import SanitizedAgentContext
from agents.agent1_evidence_intelligence.schemas import Agent1Claim, Agent1Output

logger = logging.getLogger(__name__)


class Agent1Validator:
    """
    Deterministic validator wrapping LLM output for Agent 1.
    Prevents hallucinated evidence references and invalid confidence values from entering system of record.
    """

    @staticmethod
    def extract_valid_id_universe(findings: List[Any]) -> Tuple[Set[str], Set[str]]:
        """
        Extracts all valid finding_ids and valid source evidence_ids from supplied FIR findings or SanitizedAgentContexts.
        Returns:
            (valid_finding_ids, valid_evidence_lineage_ids)
        """
        finding_ids: Set[str] = set()
        lineage_ids: Set[str] = set()

        for f in findings:
            fid = getattr(f, "finding_id", None)
            if fid:
                finding_ids.add(str(fid).strip())

            # Source artifact ID
            src_art = getattr(f, "source_artifact_id", None)
            if src_art:
                lineage_ids.add(str(src_art).strip())

            # Evidence reference list / string
            ev_ref = getattr(f, "evidence_reference", [])
            if isinstance(ev_ref, str):
                for item in ev_ref.split(","):
                    if item.strip():
                        lineage_ids.add(item.strip())
            elif isinstance(ev_ref, list):
                for item in ev_ref:
                    if item and str(item).strip():
                        lineage_ids.add(str(item).strip())

        return finding_ids, lineage_ids

    def verify_semantic_support(
        self,
        claim: Agent1Claim,
        fir_map: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Separate verification step for semantic support vs citation validity.
        Citation existence alone does NOT constitute semantic support proof.
        """
        if not claim.cited_evidence_ids:
            return False, "No cited evidence IDs provided for semantic verification."

        supported_citations = 0
        missing_citations = []

        for cid in claim.cited_evidence_ids:
            fir = fir_map.get(cid) if isinstance(fir_map, dict) else None
            if not fir:
                missing_citations.append(cid)
                continue
            
            fact = getattr(fir, "fact", "") or getattr(fir, "sanitized_fact", "") or getattr(fir, "event_summary", "")
            if fact:
                supported_citations += 1

        if missing_citations:
            return False, f"Missing FIR finding objects for cited IDs: {missing_citations}"

        if supported_citations == 0:
            return False, "Cited FIR findings contain no verifiable facts or metadata."

        # Architecture mandate A1-02: Do NOT falsely claim NLI semantic entailment has been proven merely because finding text exists.
        # Citation validity confirms finding ID existence. Semantic entailment requires a full NLI verifier.
        return False, f"Citation validity confirmed for {supported_citations} IDs. Full NLI semantic entailment requires Agent 7 independent verification."

    def validate_claims(
        self,
        claims: List[Agent1Claim],
        valid_finding_ids: Set[str],
        valid_lineage_ids: Set[str],
        fir_map: Optional[Dict[str, Any]] = None
    ) -> List[Agent1Claim]:
        """
        Performs deterministic validation over a list of Agent1Claim objects.
        """
        valid_universe = valid_finding_ids.union(valid_lineage_ids)
        validated_claims: List[Agent1Claim] = []

        for idx, claim in enumerate(claims):
            notes = []
            
            # ── 1. Citation Validation ─────────────────────────────────
            cited_ids = claim.cited_evidence_ids or []
            invalid_ids = [cid for cid in cited_ids if cid not in valid_universe]

            if invalid_ids:
                claim.citation_valid = False
                claim.citation_verified = False
                claim.invalid_citations = invalid_ids
                notes.append(f"Invalid cited IDs not in evidence lineage: {invalid_ids}")
                logger.warning(
                    "Claim %s cited non-existent evidence IDs: %s", claim.claim_id, invalid_ids
                )
            else:
                claim.citation_valid = True
                claim.citation_verified = True
                claim.invalid_citations = []
                notes.append("Citation verification passed.")

            # ── 2. Confidence Validation (No silent clamping!) ─────────
            raw_conf = claim.confidence_score
            if raw_conf is None or raw_conf < 0.0 or raw_conf > 1.0:
                claim.is_valid_confidence = False
                claim.raw_model_confidence = raw_conf
                notes.append(
                    f"Out-of-bounds confidence_score {raw_conf} detected (must be in [0.0, 1.0])."
                )
                logger.warning(
                    "Claim %s produced out-of-bounds confidence %s. Preserving raw value without silent clamping.",
                    claim.claim_id, raw_conf
                )
                # Set confidence to 0.0 for safety downstream while preserving raw_model_confidence
                claim.confidence_score = 0.0
            else:
                claim.is_valid_confidence = True
                claim.raw_model_confidence = raw_conf

            # ── 3. Priority Reason Validation ─────────────────────────
            if claim.assessed_importance in ("critical", "high") and not claim.importance_reason:
                claim.importance_reason = f"Assessed as {claim.assessed_importance} based on cited evidence: {claim.cited_evidence_ids}"

            # ── 4. Independent Claim Semantic Support Verification ────
            if fir_map:
                is_sem_valid, sem_note = self.verify_semantic_support(claim, fir_map)
                claim.semantic_support_verified = is_sem_valid
                claim.semantic_support_notes = sem_note
                notes.append(f"Semantic Support: {sem_note}")
            else:
                claim.semantic_support_verified = False
                claim.semantic_support_notes = "Citation validity confirmed (FIR map not provided for deep semantic audit)."

            claim.validation_notes = " | ".join(notes)
            validated_claims.append(claim)

        return validated_claims

