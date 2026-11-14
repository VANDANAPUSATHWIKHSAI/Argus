"""
Agent 3 — Attack Reconstruction Validator
==========================================
Deterministic validation logic for Agent 3. Enforces citation verification,
schema normalization, and grounded confidence calculation.
"""

import math
import logging
from typing import List, Set, Tuple, Any, Dict, Optional
from agents.agent3_attack_reconstruction.schemas import (
    Agent3Output, InfectionPath, AttackPathStep, AttackTimelineEvent, AttackChainStage, LateralMovement, MissingExpectedEvent
)
from infrastructure.repository.evidence_store import DELETED_EVIDENCE_IDS

logger = logging.getLogger(__name__)

def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class Agent3Validator:

    @staticmethod
    def parse_and_validate_confidence(
        val: Any,
        default: Optional[float] = 0.85,
        allow_none: bool = False
    ) -> float:
        """
        Parses and strictly validates confidence score.
        - None: applies documented default if default is not None; else raises ValueError.
        - 0.0: strictly preserved as 0.0.
        - 0.0 <= val <= 1.0: preserved.
        - Negative, > 1.0, NaN, Infinity: raises ValueError (rejected).
        """
        if val is None:
            if allow_none and default is None:
                return 0.0
            if default is not None:
                return float(default)
            raise ValueError("Confidence value cannot be None without an explicit default.")

        try:
            f_val = float(val)
        except (TypeError, ValueError) as err:
            raise ValueError(f"Invalid confidence format: {val}") from err

        if math.isnan(f_val) or math.isinf(f_val):
            raise ValueError(f"Confidence value cannot be NaN or Infinite: {val}")

        if f_val < 0.0 or f_val > 1.0:
            raise ValueError(f"Confidence value must be strictly between 0.0 and 1.0, got: {f_val}")

        return round(f_val, 4)

    @staticmethod
    def extract_valid_id_universe(
        findings: List[Any],
        case_id: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> Tuple[Set[str], Set[str]]:
        """
        Extracts valid finding and lineage IDs, enforcing case and tenant isolation when provided.
        """
        finding_ids: Set[str] = set()
        lineage_ids: Set[str] = set()

        for f in findings:
            # Enforce case isolation
            if case_id is not None:
                f_case = _get_val(f, "case_id")
                if f_case and str(f_case) != str(case_id):
                    continue
            # Enforce tenant isolation
            if tenant_id is not None and str(tenant_id) != "default":
                f_tenant = _get_val(f, "tenant_id")
                if f_tenant and str(f_tenant) != str(tenant_id):
                    continue

            fid = _get_val(f, "finding_id")
            if fid and str(fid).strip() not in DELETED_EVIDENCE_IDS:
                finding_ids.add(str(fid).strip())

            src_art = _get_val(f, "source_artifact_id")
            if src_art and str(src_art).strip() not in DELETED_EVIDENCE_IDS:
                lineage_ids.add(str(src_art).strip())

            ev_ref = _get_val(f, "evidence_reference", [])
            if isinstance(ev_ref, str):
                for item in ev_ref.split(","):
                    clean_item = item.strip()
                    if clean_item and clean_item not in DELETED_EVIDENCE_IDS:
                        lineage_ids.add(clean_item)
            elif isinstance(ev_ref, list):
                for item in ev_ref:
                    clean_item = str(item).strip() if item else ""
                    if clean_item and clean_item not in DELETED_EVIDENCE_IDS:
                        lineage_ids.add(clean_item)

        return finding_ids, lineage_ids

    def normalize_raw_dict(self, data: Dict[str, Any], valid_universe: Set[str]) -> Dict[str, Any]:
        """
        Normalizes arbitrary LLM JSON output dictionaries into clean schema format.
        Preserves confidence 0.0, rejects invalid confidence, and NEVER invents evidence IDs.
        """
        if not isinstance(data, dict):
            data = {}

        exec_status = data.get("execution_status")
        is_model_unavailable = (exec_status == "MODEL_UNAVAILABLE")
        default_conf = 0.0 if is_model_unavailable else 0.85

        def _clean_ids(ids_val: Any) -> Tuple[List[str], List[str]]:
            if isinstance(ids_val, str):
                raw_ids = [x.strip() for x in ids_val.split(",") if x.strip()]
            elif isinstance(ids_val, list):
                raw_ids = [str(x).strip() for x in ids_val if str(x).strip()]
            else:
                raw_ids = []

            valid_ids = []
            invalid_ids = []
            for cid in raw_ids:
                if not cid:
                    continue
                if valid_universe and cid not in valid_universe:
                    invalid_ids.append(cid)
                else:
                    valid_ids.append(cid)

            # Strict rule: NEVER fall back to arbitrary IDs. Empty remains empty.
            return valid_ids, invalid_ids

        # 1. Infection Path normalization
        inf_dict = data.get("infection_path") or {}
        if not isinstance(inf_dict, dict):
            inf_dict = {"entry_point": str(inf_dict)}

        entry_point = inf_dict.get("entry_point") or inf_dict.get("summary") or inf_dict.get("event") or "Initial evidence entry"
        inf_valid_ids, inf_invalid_ids = _clean_ids(inf_dict.get("evidence_ids") or inf_dict.get("citations") or inf_dict.get("evidence"))
        raw_inf_conf = inf_dict.get("confidence")
        inf_conf = self.parse_and_validate_confidence(raw_inf_conf, default=default_conf)

        data["infection_path"] = {
            "entry_point": str(entry_point),
            "evidence_ids": inf_valid_ids,
            "invalid_citations": inf_invalid_ids,
            "confidence": inf_conf,
            "citation_verified": bool(inf_valid_ids and not inf_invalid_ids)
        }

        # 2. Attack Path normalization
        raw_path = data.get("attack_path") or []
        cleaned_path = []
        if isinstance(raw_path, list):
            for idx, item in enumerate(raw_path, 1):
                if isinstance(item, dict):
                    step_num = int(item.get("step_number") or idx)
                    stg = str(item.get("stage") or item.get("phase") or "Execution")
                    desc = str(item.get("description") or item.get("event") or item.get("summary") or f"Attack step {idx}")
                    step_valid_ids, step_invalid_ids = _clean_ids(item.get("evidence_ids") or item.get("citations") or item.get("evidence"))
                    raw_step_conf = item.get("confidence")
                    step_conf = self.parse_and_validate_confidence(raw_step_conf, default=default_conf)

                    cleaned_path.append({
                        "step_number": step_num,
                        "stage": stg,
                        "description": desc,
                        "evidence_ids": step_valid_ids,
                        "invalid_citations": step_invalid_ids,
                        "confidence": step_conf,
                        "citation_verified": bool(step_valid_ids and not step_invalid_ids)
                    })
        data["attack_path"] = cleaned_path

        # 3. Attack Timeline normalization
        raw_timeline = data.get("attack_timeline") or []
        cleaned_timeline = []
        if isinstance(raw_timeline, list):
            for item in raw_timeline:
                if isinstance(item, dict):
                    ts = str(item.get("timestamp") or item.get("time") or "2026-10-03T00:00:00Z")
                    evt = str(item.get("event") or item.get("summary") or item.get("description") or "Event")
                    stg = str(item.get("stage") or item.get("phase") or "Execution")
                    evt_valid_ids, evt_invalid_ids = _clean_ids(item.get("evidence_ids") or item.get("citations") or item.get("evidence"))
                    raw_evt_conf = item.get("confidence")
                    evt_conf = self.parse_and_validate_confidence(raw_evt_conf, default=default_conf)

                    cleaned_timeline.append({
                        "timestamp": ts,
                        "event": evt,
                        "stage": stg,
                        "evidence_ids": evt_valid_ids,
                        "invalid_citations": evt_invalid_ids,
                        "confidence": evt_conf,
                        "citation_verified": bool(evt_valid_ids and not evt_invalid_ids)
                    })
        data["attack_timeline"] = cleaned_timeline

        # Auto-derive attack_path steps if LLM put sequence in timeline instead of attack_path
        if not cleaned_path and cleaned_timeline and not is_model_unavailable:
            for idx, item in enumerate(cleaned_timeline, 1):
                cleaned_path.append({
                    "step_number": idx,
                    "stage": item["stage"],
                    "description": item["event"],
                    "evidence_ids": item["evidence_ids"],
                    "invalid_citations": item.get("invalid_citations", []),
                    "confidence": item["confidence"],
                    "citation_verified": item.get("citation_verified", False)
                })
            data["attack_path"] = cleaned_path

        # 4. Attack Chain normalization
        raw_chain = data.get("attack_chain") or []
        cleaned_chain = []
        if isinstance(raw_chain, list):
            for item in raw_chain:
                if isinstance(item, dict):
                    stg = str(item.get("stage") or item.get("name") or "Execution")
                    evts_val = item.get("events") or item.get("event_list") or []
                    if isinstance(evts_val, str):
                        evts = [evts_val]
                    elif isinstance(evts_val, list):
                        evts = [str(x) for x in evts_val]
                    else:
                        evts = [stg]
                    chain_valid_ids, chain_invalid_ids = _clean_ids(item.get("evidence_ids") or item.get("citations") or item.get("evidence"))
                    raw_chain_conf = item.get("confidence")
                    chain_conf = self.parse_and_validate_confidence(raw_chain_conf, default=default_conf)

                    cleaned_chain.append({
                        "stage": stg,
                        "events": evts,
                        "evidence_ids": chain_valid_ids,
                        "invalid_citations": chain_invalid_ids,
                        "confidence": chain_conf,
                        "citation_verified": bool(chain_valid_ids and not chain_invalid_ids)
                    })
        data["attack_chain"] = cleaned_chain

        # 5. Lateral Movement normalization
        raw_lm = data.get("lateral_movement") or []
        cleaned_lm = []
        if isinstance(raw_lm, list):
            for item in raw_lm:
                if isinstance(item, dict):
                    src = str(item.get("source_host") or item.get("src") or item.get("source") or "Host-A")
                    dst = str(item.get("destination_host") or item.get("dst") or item.get("destination") or "Host-B")
                    meth = str(item.get("method") or item.get("protocol") or "SMB")
                    lm_valid_ids, lm_invalid_ids = _clean_ids(item.get("evidence_ids") or item.get("citations") or item.get("evidence"))
                    raw_lm_conf = item.get("confidence")
                    lm_conf = self.parse_and_validate_confidence(raw_lm_conf, default=default_conf)

                    cleaned_lm.append({
                        "source_host": src,
                        "destination_host": dst,
                        "method": meth,
                        "evidence_ids": lm_valid_ids,
                        "invalid_citations": lm_invalid_ids,
                        "confidence": lm_conf,
                        "citation_verified": bool(lm_valid_ids and not lm_invalid_ids)
                    })
        data["lateral_movement"] = cleaned_lm

        # 6. Missing Expected Events normalization
        raw_missing = data.get("missing_expected_events") or []
        cleaned_missing = []
        if isinstance(raw_missing, list):
            for item in raw_missing:
                if isinstance(item, dict):
                    evt = str(item.get("event") or item.get("description") or "Missing event")
                    rsn = str(item.get("reason") or item.get("explanation") or "Not found in logs")
                    cleaned_missing.append({
                        "event": evt,
                        "reason": rsn,
                        "status": "NOT_OBSERVED"
                    })
        data["missing_expected_events"] = cleaned_missing

        data["reconstruction_summary"] = str(data.get("reconstruction_summary") or "Attack reconstruction synthesized from evidence findings.")
        raw_overall = data.get("overall_confidence")
        data["overall_confidence"] = self.parse_and_validate_confidence(raw_overall, default=default_conf)

        return data

    def validate_citations(
        self,
        component: Any,
        valid_universe: Set[str]
    ):
        """Validates citations in a single component and records diagnostics."""
        cited_ids = list(getattr(component, "evidence_ids", []) or [])
        invalid_ids = [cid for cid in cited_ids if cid not in valid_universe]

        if invalid_ids:
            component.citation_verified = False
            component.invalid_citations = invalid_ids
            component.evidence_ids = [cid for cid in cited_ids if cid not in invalid_ids]
            logger.warning("Agent 3 rejected invalid/unknown evidence citations: %s", invalid_ids)
        else:
            component.citation_verified = bool(cited_ids)
            component.invalid_citations = []

        raw_conf = getattr(component, "confidence", None)
        if raw_conf is not None:
            # Re-validate strictly; rejects negative, > 1.0, NaN, inf
            component.confidence = self.parse_and_validate_confidence(raw_conf, default=0.85)

    def validate_output(
        self,
        output: Agent3Output,
        valid_finding_ids: Set[str],
        valid_lineage_ids: Set[str]
    ) -> Agent3Output:
        valid_universe = valid_finding_ids.union(valid_lineage_ids)

        self.validate_citations(output.infection_path, valid_universe)
        for step in output.attack_path:
            self.validate_citations(step, valid_universe)
        for evt in output.attack_timeline:
            self.validate_citations(evt, valid_universe)
        for stg in output.attack_chain:
            self.validate_citations(stg, valid_universe)
        for lm in output.lateral_movement:
            self.validate_citations(lm, valid_universe)

        # Grounded overall confidence score computation
        all_components = [output.infection_path] + output.attack_path + output.attack_timeline + output.attack_chain + output.lateral_movement
        
        if getattr(output, "execution_status", "") in ("FAILED", "MODEL_UNAVAILABLE", "EXECUTION_FAILED", "VALIDATION_FAILED"):
            output.overall_confidence = 0.0
        elif all_components:
            verified_count = sum(1 for c in all_components if getattr(c, "citation_verified", False))
            total_count = len(all_components)
            citation_ratio = verified_count / total_count
            avg_conf = sum(getattr(c, "confidence", 0.0) for c in all_components) / total_count
            if verified_count == 0 or avg_conf == 0.0:
                output.overall_confidence = 0.0
            else:
                output.overall_confidence = min(0.95, round(citation_ratio * avg_conf, 2))
        else:
            output.overall_confidence = 0.0

        # Refine execution status based on findings & citation health
        current_st = output.execution_status
        if current_st not in ("FAILED", "MODEL_UNAVAILABLE", "EXECUTION_FAILED", "VALIDATION_FAILED"):
            has_steps = bool(output.attack_path or output.attack_timeline)
            all_verified = all_components and all(getattr(c, "citation_verified", False) for c in all_components if getattr(c, "evidence_ids", []))
            
            if has_steps:
                if all_verified and output.overall_confidence >= 0.50:
                    output.execution_status = "COMPLETED_WITH_FINDINGS"
                else:
                    output.execution_status = "NEEDS_REVIEW"
            else:
                output.execution_status = "COMPLETED_WITH_NO_FINDINGS"

        return output
