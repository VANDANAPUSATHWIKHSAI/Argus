# Agent 6 — Impact Assessment
# Affected assets, user/business impact, severity scoring, recovery recommendations.
# Strictly evidence-grounded: requires verified current-case FIR records.
# Prohibits asserting asset compromise solely from historical campaign similarity.
# Model: Qwen3-14B | Sanitization Gateway | Tenant Isolation enforced

import logging
import re
from typing import List, Dict, Any, Set, Optional

from agents.base_agent import BaseAgent
from agents.agent6_impact_assessment.schemas import (
    AssetImpactDetail,
    ImmediateRecommendation,
    ImpactAssessmentOutput
)

logger = logging.getLogger("argus.agent6")


class ImpactAssessmentAgent(BaseAgent):
    """
    Agent 6 evaluates business impact, asset compromise, and remediation priorities.
    Enforces strict evidence grounding: assets must be corroborated by current-case FIR findings.
    """

    def __init__(
        self,
        model,
        fir_repo=None,
        sanitization_gateway=None,
        tenant_id: str = "default"
    ):
        super().__init__(
            model=model,
            fir_repo=fir_repo,
            sanitization_gateway=sanitization_gateway,
            tenant_id=tenant_id
        )

    def run(self, case_id: str, context: dict) -> dict:
        """
        Executes evidence-grounded impact assessment.
        Returns BaseAgent compliant dict containing structured impact evaluation.
        """
        target_tenant = context.get("tenant_id") or self.tenant_id or "default"
        raw_assets = context.get("affected_assets", [])

        # 1. Collect all authorized current-case FIR findings and evidence references
        authorized_findings_by_id: Dict[str, Any] = {}
        findings_list: List[Any] = []

        # From FIR repo if attached
        if self.fir and hasattr(self.fir, "get_all_by_case"):
            try:
                repo_findings = self.fir.get_all_by_case(target_tenant, case_id)
                for f in repo_findings:
                    fid = getattr(f, "finding_id", None) or (f.get("finding_id") if isinstance(f, dict) else "")
                    if fid:
                        authorized_findings_by_id[fid] = f
                        findings_list.append(f)
            except Exception as e:
                logger.warning(f"Error fetching case findings from FIR repository: {e}")

        # From context findings if provided directly
        ctx_findings = context.get("fir_findings") or context.get("evidence") or []
        for f in ctx_findings:
            if isinstance(f, dict):
                # Tenant isolation check
                f_tenant = f.get("tenant_id")
                if f_tenant and f_tenant != target_tenant:
                    continue  # Cross-tenant evidence strictly ignored
                fid = f.get("finding_id", "")
                if fid:
                    authorized_findings_by_id[fid] = f
                    findings_list.append(f)

        # From upstream handoff supporting references
        handoff = (
            context.get("agent5b_handoff") or
            context.get("agent5b_output", {}).get("agent6_handoff") or
            {}
        )
        handoff_eids = set(handoff.get("supporting_evidence_references", []))

        # 2. Extract and sanitize asset list
        sanitized_asset_names = self._extract_asset_names(raw_assets)

        # 3. Ground each asset against actual current-case evidence
        asset_impacts: List[AssetImpactDetail] = []
        confirmed_evidence_ids: Set[str] = set()
        confirmed_findings_text: List[str] = []

        for asset_name in sanitized_asset_names:
            matched_eids: Set[str] = set()
            observed_facts: List[str] = []

            # A. Check FIR findings mentioning this asset
            clean_name = asset_name.strip()
            for fid, f in authorized_findings_by_id.items():
                fact_text = ""
                if hasattr(f, "sanitized_fact") and f.sanitized_fact:
                    fact_text = f.sanitized_fact
                elif hasattr(f, "fact") and f.fact:
                    fact_text = f.fact
                elif isinstance(f, dict):
                    fact_text = f.get("sanitized_fact") or f.get("fact") or ""

                # Case-insensitive token/substring match for hostname
                if clean_name.lower() in fact_text.lower():
                    matched_eids.add(fid)
                    observed_facts.append(fact_text)

            # B. Check explicit asset dictionary evidence mapping if provided in raw_assets
            for raw_item in raw_assets:
                if isinstance(raw_item, dict):
                    item_name = raw_item.get("asset_name") or raw_item.get("asset") or ""
                    if item_name.strip().lower() == clean_name.lower():
                        c_eids = raw_item.get("evidence_ids", [])
                        for eid in c_eids:
                            # Verify eid belongs to current case & tenant
                            if eid in authorized_findings_by_id or eid in handoff_eids:
                                matched_eids.add(eid)
                                if eid in authorized_findings_by_id:
                                    f_obj = authorized_findings_by_id[eid]
                                    txt = getattr(f_obj, "fact", "") if hasattr(f_obj, "fact") else f_obj.get("fact", "")
                                    if txt and txt not in observed_facts:
                                        observed_facts.append(txt)

            # C. Classify Asset Compromise Status
            if matched_eids:
                status = "confirmed_compromise"
                severity = "critical" if any(w in " ".join(observed_facts).lower() for w in ["c2", "persistence", "powershell", "lsass", "dump", "updater"]) else "high"
                rationale = f"Observed forensic artifact(s) on asset '{clean_name}' corroborate compromise."
                confirmed_evidence_ids.update(matched_eids)
                confirmed_findings_text.extend(observed_facts)
            else:
                status = "unsupported_in_evidence"
                severity = "low"
                rationale = (
                    f"Asset '{clean_name}' does not appear in any authorized current-case FIR findings or telemetry. "
                    "Cannot infer confirmed compromise without supporting evidence."
                )

            asset_impacts.append(AssetImpactDetail(
                asset_name=clean_name,
                status=status,
                supporting_evidence_ids=sorted(list(matched_eids)),
                observed_facts=observed_facts[:3],
                severity=severity,
                rationale=rationale
            ))

        # 4. Formulate Immediate Recommendations (Clearly Distinguished from Confirmed Compromise)
        recommendations: List[ImmediateRecommendation] = []
        confirmed_assets = [a.asset_name for a in asset_impacts if a.status == "confirmed_compromise"]
        unsupported_assets = [a.asset_name for a in asset_impacts if a.status == "unsupported_in_evidence"]

        # Recommendation 1: Network containment for confirmed assets
        if confirmed_assets:
            recommendations.append(ImmediateRecommendation(
                action=f"Host Isolation & Containment for {', '.join(confirmed_assets)}",
                urgency="critical",
                supporting_indicators=sorted(list(confirmed_evidence_ids)),
                status="provisional_recommended",
                rationale="Forensic evidence confirms malware activity on these hosts. Immediate isolation prevents lateral spread."
            ))

        # Recommendation 2: Credential revocation based on observed behaviors
        observed_behaviors = handoff.get("behavior_comparisons", {})
        all_curr_b = observed_behaviors.get("common_behaviors", []) + observed_behaviors.get("new_behaviors", [])
        has_cred_theft = any("lsass" in b.lower() or "credential" in b.lower() for b in all_curr_b)

        if has_cred_theft or confirmed_assets:
            recommendations.append(ImmediateRecommendation(
                action="Enterprise Credential Revocation for Logged-In User Sessions",
                urgency="high",
                supporting_indicators=["Credential access mechanism detected in investigation scope"],
                status="provisional_recommended",
                rationale="Credential theft mechanism observed in incident; rotate privileged and active user passwords."
            ))

        # Recommendation 3: Forensic triage for unconfirmed assets
        if unsupported_assets:
            recommendations.append(ImmediateRecommendation(
                action=f"Targeted Forensic Telemetry Collection on {', '.join(unsupported_assets)}",
                urgency="medium",
                supporting_indicators=[],
                status="contingent_on_investigation",
                rationale=f"Assets {', '.join(unsupported_assets)} were flagged for review but lack confirmed forensic evidence. Do not isolate until artifacts are established."
            ))

        # 5. Determine Structured Validation Status
        if not asset_impacts or not confirmed_assets:
            validation_status = "insufficient_evidence"
        elif unsupported_assets:
            validation_status = "partially_supported"
        else:
            validation_status = "supported"

        # 6. Formulate Narrative Claim Grounded in Evidence
        claim = self._build_grounded_claim(
            confirmed_assets=confirmed_assets,
            unsupported_assets=unsupported_assets,
            evidence_ids=sorted(list(confirmed_evidence_ids)),
            handoff=handoff,
            validation_status=validation_status
        )

        limitations = [
            "Asset compromise is asserted only when corroborated by current-case FIR records.",
            "Historical campaign similarity and threat intelligence resemblance are contextual profiling only, never proof of asset compromise.",
            "Immediate recommendations are risk-calibrated containment steps, distinct from verified forensic facts."
        ]

        output = ImpactAssessmentOutput(
            case_id=case_id,
            tenant_id=target_tenant,
            claim=claim,
            evidence_ids=sorted(list(confirmed_evidence_ids)),
            validation_status=validation_status,
            asset_impacts=asset_impacts,
            confirmed_findings=sorted(list(set(confirmed_findings_text))),
            immediate_recommendations=recommendations,
            limitations=limitations
        )

        return output.model_dump()

    def _extract_asset_names(self, raw_assets: Any) -> List[str]:
        """Extracts and sanitizes unique asset names from input structure."""
        names = []
        if isinstance(raw_assets, list):
            for item in raw_assets:
                if isinstance(item, str):
                    clean = item.strip()
                    if clean and clean not in names:
                        names.append(clean)
                elif isinstance(item, dict):
                    name = item.get("asset_name") or item.get("asset") or item.get("hostname") or ""
                    clean = str(name).strip()
                    if clean and clean not in names:
                        names.append(clean)
        elif isinstance(raw_assets, str) and raw_assets.strip():
            names.append(raw_assets.strip())

        return names

    def _build_grounded_claim(
        self,
        confirmed_assets: List[str],
        unsupported_assets: List[str],
        evidence_ids: List[str],
        handoff: Dict[str, Any],
        validation_status: str
    ) -> str:
        """Constructs an auditable, evidence-grounded claim."""
        eids_str = ", ".join(evidence_ids) if evidence_ids else "none"

        if validation_status == "supported":
            return (
                f"Forensic evidence ({eids_str}) confirms active compromise on asset(s): {', '.join(confirmed_assets)}. "
                "Immediate containment and credential revocation recommended."
            )
        elif validation_status == "partially_supported":
            return (
                f"Forensic evidence ({eids_str}) confirms compromise on asset(s): {', '.join(confirmed_assets)}. "
                f"Asset(s) {', '.join(unsupported_assets)} lack supporting evidence in current-case records and remain "
                "unconfirmed pending forensic triage. Immediate containment recommended for confirmed asset(s) only."
            )
        else:
            unsupported_str = ", ".join(unsupported_assets) if unsupported_assets else "all specified assets"
            return (
                f"Insufficient current-case evidence to confirm compromise on {unsupported_str}. "
                "Historical campaign similarity provides risk context but does not establish confirmed compromise "
                "without supporting FIR evidence."
            )
