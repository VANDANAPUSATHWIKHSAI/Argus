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
    def extract_valid_id_universe(
        findings: List[Any],
        tenant_id: Optional[str] = None,
        case_id: Optional[str] = None
    ) -> Tuple[Set[str], Set[str]]:
        """
        Extracts all valid finding_ids and valid source evidence_ids from supplied FIR findings or SanitizedAgentContexts.
        Enforces tenant and case boundary filtering when provided.
        Returns:
            (valid_finding_ids, valid_evidence_lineage_ids)
        """
        finding_ids: Set[str] = set()
        lineage_ids: Set[str] = set()

        for f in findings:
            f_tenant = _get_val(f, "tenant_id")
            if tenant_id and f_tenant and f_tenant != tenant_id and tenant_id != "default":
                continue

            f_case = _get_val(f, "case_id")
            if case_id and f_case and str(f_case) != str(case_id):
                continue

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

    @staticmethod
    def calculate_deterministic_priority_score(
        investigative_value: str = "MEDIUM",
        severity: str = "informational",
        has_provenance: bool = True,
        has_timestamp: bool = True,
        has_multiple_refs: bool = False,
        is_primary_or_supporting: bool = True
    ) -> Tuple[float, List[str]]:
        """
        Calculates an explainable, deterministic priority score in [0.0, 1.0] with explicit factor breakdown.
        Factor weights:
        - relevance (investigative_value): 0.25
        - evidentiary_strength (severity & provenance): 0.25
        - temporal_relevance (has timestamp): 0.15
        - cross_source_support (multiple evidence refs): 0.15
        - downstream_usefulness: 0.10
        - evidence_gap_contribution: 0.10
        """
        val_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2, "INFORMATIONAL": 0.1}
        rel_factor = val_map.get(str(investigative_value).upper(), 0.5)

        sev_map = {"critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.3, "informational": 0.1}
        sev_factor = sev_map.get(str(severity).lower(), 0.5)
        prov_factor = 1.0 if has_provenance else 0.4
        strength_factor = (sev_factor + prov_factor) / 2.0

        ts_factor = 1.0 if has_timestamp else 0.0
        cross_factor = 1.0 if has_multiple_refs else 0.5
        downstream_factor = 1.0 if is_primary_or_supporting else 0.5
        gap_factor = 1.0 if is_primary_or_supporting else 0.5

        raw_score = (
            0.25 * rel_factor +
            0.25 * strength_factor +
            0.15 * ts_factor +
            0.15 * cross_factor +
            0.10 * downstream_factor +
            0.10 * gap_factor
        )
        score = round(max(0.0, min(1.0, raw_score)), 2)

        breakdown = [
            f"investigative_relevance={investigative_value} ({rel_factor:.2f})",
            f"evidentiary_strength={strength_factor:.2f}",
            f"temporal_relevance={ts_factor:.2f}",
            f"cross_source_support={cross_factor:.2f}",
            f"downstream_usefulness={downstream_factor:.2f}"
        ]
        return score, breakdown

    def validate_triage_output(
        self,
        output_dict: Dict[str, Any],
        valid_finding_ids: Set[str],
        valid_lineage_ids: Set[str]
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Performs strict Evidence Reference Gate validation across all output components.
        Rejects triage items with empty evidence_ids.
        Preserves raw priority scores without silent clamping.
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
                    if not eid:
                        invalid_citations.add("<empty_evidence_id>")
                        logger.warning("Agent1Validator: priority_evidence rejected due to empty evidence_id")
                        continue
                    if eid not in valid_universe:
                        invalid_citations.add(eid)
                        logger.warning("Agent1Validator: priority_evidence cited invalid ID '%s'", eid)
                        continue

                    inv_val = item.get("investigative_value", "MEDIUM")
                    score = item.get("priority_score")
                    reasons = item.get("reason", [])
                    if not isinstance(reasons, list):
                        reasons = [str(reasons)] if reasons else []

                    if score is None:
                        score, breakdown = self.calculate_deterministic_priority_score(investigative_value=inv_val)
                        reasons.extend(breakdown)
                    else:
                        try:
                            parsed_score = float(score)
                            item["raw_priority_score"] = parsed_score
                            if parsed_score < 0.0 or parsed_score > 1.0:
                                reasons.append(f"Priority score {parsed_score} out of bounds [0.0, 1.0]; recomputed deterministically.")
                                score, breakdown = self.calculate_deterministic_priority_score(investigative_value=inv_val)
                                reasons.extend(breakdown)
                            else:
                                score = parsed_score
                        except (ValueError, TypeError):
                            score, breakdown = self.calculate_deterministic_priority_score(investigative_value=inv_val)
                            reasons.extend(breakdown)

                    item["priority_score"] = score
                    item["reason"] = reasons
                    cleaned_priority.append(item)
            output_dict["priority_evidence"] = cleaned_priority

        # 2. Validate supporting_evidence
        supporting_ev = output_dict.get("supporting_evidence", [])
        if isinstance(supporting_ev, list):
            cleaned_supporting = []
            for item in supporting_ev:
                if isinstance(item, dict):
                    eid = str(item.get("evidence_id", "")).strip()
                    if not eid:
                        invalid_citations.add("<empty_evidence_id>")
                        continue
                    if eid not in valid_universe:
                        invalid_citations.add(eid)
                        continue

                    # Validate supported IDs
                    supports = item.get("supports", [])
                    valid_supports = []
                    if isinstance(supports, list):
                        for s in supports:
                            s_str = str(s).strip()
                            if not s_str:
                                invalid_citations.add("<empty_supported_id>")
                            elif s_str not in valid_universe:
                                invalid_citations.add(s_str)
                            else:
                                valid_supports.append(s_str)
                    item["supports"] = valid_supports
                    cleaned_supporting.append(item)
            output_dict["supporting_evidence"] = cleaned_supporting

        # 3. Validate evidence_clusters
        clusters = output_dict.get("evidence_clusters", [])
        if isinstance(clusters, list):
            cleaned_clusters = []
            for item in clusters:
                if isinstance(item, dict):
                    eids = item.get("evidence_ids", [])
                    valid_eids = []
                    for eid in eids:
                        eid_str = str(eid).strip()
                        if not eid_str:
                            invalid_citations.add("<empty_cluster_evidence_id>")
                        elif eid_str not in valid_universe:
                            invalid_citations.add(eid_str)
                        else:
                            valid_eids.append(eid_str)
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
                    valid_eids = []
                    for eid in eids:
                        eid_str = str(eid).strip()
                        if not eid_str:
                            invalid_citations.add("<empty_question_evidence_id>")
                        elif eid_str not in valid_universe:
                            invalid_citations.add(eid_str)
                        else:
                            valid_eids.append(eid_str)
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
                    valid_eids = []
                    for eid in eids:
                        eid_str = str(eid).strip()
                        if not eid_str:
                            invalid_citations.add("<empty_focus_evidence_id>")
                        elif eid_str not in valid_universe:
                            invalid_citations.add(eid_str)
                        else:
                            valid_eids.append(eid_str)
                    item["evidence_ids"] = valid_eids
                    cleaned_focus.append(item)
            output_dict["focus_areas"] = cleaned_focus

        # 6. Validate downstream_relevance
        relevance = output_dict.get("downstream_relevance", {})
        if isinstance(relevance, dict):
            cleaned_rel = {}
            for agent_key, eids in relevance.items():
                if isinstance(eids, list):
                    valid_eids = []
                    for eid in eids:
                        eid_str = str(eid).strip()
                        if not eid_str:
                            invalid_citations.add("<empty_downstream_evidence_id>")
                        elif eid_str not in valid_universe:
                            invalid_citations.add(eid_str)
                        else:
                            valid_eids.append(eid_str)
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
        Enforces:
        - Claims with zero evidence IDs NEVER receive citation_valid=True or citation_verified=True.
        - Missing confidence is preserved as None and marked invalid/missing.
        """
        valid_universe = valid_finding_ids.union(valid_lineage_ids)
        validated_claims: List[Agent1Claim] = []

        for claim in claims:
            raw_cited = claim.cited_evidence_ids or []
            cleaned_cited = [str(cid).strip() for cid in raw_cited if cid and str(cid).strip()]

            notes = []
            if not raw_cited or not cleaned_cited:
                claim.citation_valid = False
                claim.citation_verified = False
                claim.invalid_citations = []
                notes.append("Claim cites zero evidence IDs: citation verification failed.")
            else:
                invalid_ids = [cid for cid in cleaned_cited if cid not in valid_universe]
                if len(raw_cited) > len(cleaned_cited):
                    invalid_ids.append("<empty_evidence_id>")

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
            if raw_conf is None:
                claim.is_valid_confidence = False
                claim.raw_model_confidence = None
                claim.confidence_score = None
                notes.append("Missing confidence_score: model did not supply confidence.")
            elif raw_conf < 0.0 or raw_conf > 1.0:
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
