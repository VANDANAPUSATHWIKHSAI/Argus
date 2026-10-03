"""
Agent 1 — Evidence Intelligence & Triage Validator
===================================================
Deterministic validation logic for Agent 1. Enforces:
  1. Strict Evidence Reference Validation: Every cited ID in priority_evidence,
     clusters, questions, focus_areas, and downstream_relevance MUST exist in FIR.
  2. Rejects hallucinated evidence IDs without fabricating fake replacements.
  3. Priority score range validation [0.0, 1.0].
  4. Preserves evidence integrity and validation error visibility.
"""

import logging
from typing import List, Set, Tuple, Any, Dict, Optional
from fir.schemas import FIRFinding
from sanitization.gateway import SanitizedAgentContext
from agents.agent1_evidence_intelligence.schemas import (
    Agent1Output,
    Agent1EvidenceAssessment,
    Agent1EvidenceCluster,
    Agent1InvestigationQuestion,
    Agent1FocusArea,
    Agent1Claim
)

logger = logging.getLogger(__name__)


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class Agent1Validator:
    """
    Deterministic validator wrapping LLM output for Agent 1.
    Enforces Evidence Reference Gate rules and structural validity.
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
            fid = _get_val(f, "finding_id")
            if fid:
                finding_ids.add(str(fid).strip())

            # Source artifact ID
            src_art = _get_val(f, "source_artifact_id")
            if src_art:
                lineage_ids.add(str(src_art).strip())

            # Evidence reference list / string
            ev_ref = _get_val(f, "evidence_reference", [])
            if isinstance(ev_ref, str):
                for item in ev_ref.split(","):
                    if item.strip():
                        lineage_ids.add(item.strip())
            elif isinstance(ev_ref, list):
                for item in ev_ref:
                    if item and str(item).strip():
                        lineage_ids.add(str(item).strip())

        return finding_ids, lineage_ids

    def validate_triage_output(
        self,
        output_dict: Dict[str, Any],
        valid_finding_ids: Set[str],
        valid_lineage_ids: Set[str]
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Performs strict Evidence Reference Gate validation across all output components.
        Returns (validated_output_dict, invalid_citations_list).
        """
        valid_universe = valid_finding_ids.union(valid_lineage_ids)
        invalid_citations: Set[str] = set()

        # 1. Validate priority_evidence
        priority_ev = output_dict.get("priority_evidence", [])
        if isinstance(priority_ev, list):
            cleaned_priority = []
            for item in priority_ev:
                if isinstance(item, dict):
                    eid = str(item.get("evidence_id", "")).strip()
                    if eid and eid not in valid_universe:
                        invalid_citations.add(eid)
                        logger.warning("Agent1Validator: priority_evidence cited invalid ID '%s'", eid)
                    else:
                        # Validate priority_score bounds [0.0, 1.0]
                        score = item.get("priority_score", 0.5)
                        try:
                            score = float(score)
                            if score < 0.0 or score > 1.0:
                                score = max(0.0, min(1.0, score))
                        except (ValueError, TypeError):
                            score = 0.5
                        item["priority_score"] = score
                        cleaned_priority.append(item)
            output_dict["priority_evidence"] = cleaned_priority

        # 2. Validate supporting_evidence
        supporting_ev = output_dict.get("supporting_evidence", [])
        if isinstance(supporting_ev, list):
            cleaned_supporting = []
            for item in supporting_ev:
                if isinstance(item, dict):
                    eid = str(item.get("evidence_id", "")).strip()
                    if eid and eid not in valid_universe:
                        invalid_citations.add(eid)
                    else:
                        cleaned_supporting.append(item)
            output_dict["supporting_evidence"] = cleaned_supporting

        # 3. Validate evidence_clusters
        clusters = output_dict.get("evidence_clusters", [])
        if isinstance(clusters, list):
            cleaned_clusters = []
            for item in clusters:
                if isinstance(item, dict):
                    eids = item.get("evidence_ids", [])
                    valid_eids = [eid for eid in eids if str(eid).strip() in valid_universe]
                    for eid in eids:
                        if str(eid).strip() not in valid_universe:
                            invalid_citations.add(str(eid).strip())
                    item["evidence_ids"] = valid_eids
                    cleaned_clusters.append(item)
            output_dict["evidence_clusters"] = cleaned_clusters

        # 4. Validate investigation_questions
        questions = output_dict.get("investigation_questions", [])
        if isinstance(questions, list):
            cleaned_questions = []
            for item in questions:
                if isinstance(item, dict):
                    eids = item.get("evidence_ids", [])
                    valid_eids = [eid for eid in eids if str(eid).strip() in valid_universe]
                    for eid in eids:
                        if str(eid).strip() not in valid_universe:
                            invalid_citations.add(str(eid).strip())
                    item["evidence_ids"] = valid_eids
                    cleaned_questions.append(item)
            output_dict["investigation_questions"] = cleaned_questions

        # 5. Validate focus_areas
        focus_areas = output_dict.get("focus_areas", [])
        if isinstance(focus_areas, list):
            cleaned_focus = []
            for item in focus_areas:
                if isinstance(item, dict):
                    eids = item.get("evidence_ids", [])
                    valid_eids = [eid for eid in eids if str(eid).strip() in valid_universe]
                    for eid in eids:
                        if str(eid).strip() not in valid_universe:
                            invalid_citations.add(str(eid).strip())
                    item["evidence_ids"] = valid_eids
                    cleaned_focus.append(item)
            output_dict["focus_areas"] = cleaned_focus

        # 6. Validate downstream_relevance
        relevance = output_dict.get("downstream_relevance", {})
        if isinstance(relevance, dict):
            cleaned_rel = {}
            for agent_key, eids in relevance.items():
                if isinstance(eids, list):
                    valid_eids = [eid for eid in eids if str(eid).strip() in valid_universe]
                    for eid in eids:
                        if str(eid).strip() not in valid_universe:
                            invalid_citations.add(str(eid).strip())
                    cleaned_rel[agent_key] = valid_eids
                else:
                    cleaned_rel[agent_key] = []
            output_dict["downstream_relevance"] = cleaned_rel

        return output_dict, sorted(list(invalid_citations))

    def validate_claims(
        self,
        claims: List[Agent1Claim],
        valid_finding_ids: Set[str],
        valid_lineage_ids: Set[str],
        fir_map: Optional[Dict[str, Any]] = None
    ) -> List[Agent1Claim]:
        """
        Backward compatibility helper validating Agent1Claim objects.
        """
        valid_universe = valid_finding_ids.union(valid_lineage_ids)
        validated_claims: List[Agent1Claim] = []

        for claim in claims:
            cited_ids = claim.cited_evidence_ids or []
            invalid_ids = [cid for cid in cited_ids if cid not in valid_universe]

            notes = []
            if invalid_ids:
                claim.citation_valid = False
                claim.citation_verified = False
                claim.invalid_citations = invalid_ids
                notes.append(f"Invalid cited IDs not in evidence lineage: {invalid_ids}")
            else:
                claim.citation_valid = True
                claim.citation_verified = True
                claim.invalid_citations = []
                notes.append("Citation verification passed.")

            raw_conf = claim.confidence_score
            if raw_conf is None or raw_conf < 0.0 or raw_conf > 1.0:
                claim.is_valid_confidence = False
                claim.raw_model_confidence = raw_conf
                claim.confidence_score = 0.0
                notes.append(f"Out-of-bounds confidence_score {raw_conf} detected (must be in [0.0, 1.0]).")
            else:
                claim.is_valid_confidence = True
                claim.raw_model_confidence = raw_conf

            claim.validation_notes = " | ".join(notes)
            validated_claims.append(claim)

        return validated_claims
