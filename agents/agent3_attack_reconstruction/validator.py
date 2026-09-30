"""
Agent 3 — Attack Reconstruction Validator
==========================================
Deterministic validation logic for Agent 3. Enforces citation verification.
"""

import logging
from typing import List, Set, Tuple, Any
from agents.agent3_attack_reconstruction.schemas import (
    Agent3Output, InfectionPath, AttackTimelineEvent, AttackChainStage, LateralMovement
)

logger = logging.getLogger(__name__)

def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class Agent3Validator:
    @staticmethod
    def extract_valid_id_universe(findings: List[Any]) -> Tuple[Set[str], Set[str]]:
        finding_ids: Set[str] = set()
        lineage_ids: Set[str] = set()

        for f in findings:
            fid = _get_val(f, "finding_id")
            if fid:
                finding_ids.add(str(fid).strip())

            src_art = _get_val(f, "source_artifact_id")
            if src_art:
                lineage_ids.add(str(src_art).strip())

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

    def validate_citations(
        self,
        component: Any,
        valid_universe: Set[str]
    ):
        """Validates citations in a single component and updates its flags."""
        cited_ids = getattr(component, "evidence_ids", [])
        invalid_ids = [cid for cid in cited_ids if cid not in valid_universe]
        
        if invalid_ids:
            component.citation_verified = False
            component.invalid_citations = invalid_ids
            component.evidence_ids = [cid for cid in cited_ids if cid not in invalid_ids]
            logger.warning("Agent 3 cited non-existent evidence IDs: %s", invalid_ids)
        else:
            component.citation_verified = True
            component.invalid_citations = []
            
        raw_conf = getattr(component, "confidence", 0.0)
        if raw_conf is None or raw_conf < 0.0 or raw_conf > 1.0:
            component.confidence = 0.0
            
    def validate_output(
        self,
        output: Agent3Output,
        valid_finding_ids: Set[str],
        valid_lineage_ids: Set[str]
    ) -> Agent3Output:
        valid_universe = valid_finding_ids.union(valid_lineage_ids)
        
        self.validate_citations(output.infection_path, valid_universe)
        for evt in output.attack_timeline:
            self.validate_citations(evt, valid_universe)
        for stg in output.attack_chain:
            self.validate_citations(stg, valid_universe)
        for lm in output.lateral_movement:
            self.validate_citations(lm, valid_universe)
            
        return output
