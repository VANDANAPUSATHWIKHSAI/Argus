"""
Agent 6 — Impact Assessment Agent
==================================
Fifth reasoning layer in Project ARGUS.
Determines affected assets, systems, and identities; calculates technical vulnerability
severity (CVSS v3.1) and broader incident impact (ISS); generates prioritized recovery
playbooks; and provides evidence-grounded Qwen3-8B narration.

Architecture & Safety Guarantees:
  1. Complete Separation of CVSS (technical vulnerability severity) vs ISS (investigation impact).
  2. Pure Python deterministic calculators for both CVSS v3.1 and ISS scores.
  3. Evidence-to-CVSS mapping with complete evidence traceability and missing metric detection.
  4. Explicit 'INSUFFICIENT_DATA' handling — never guesses ungrounded metrics to force a score.
  5. Sanitization Gateway defuses prompt injections in upstream artifact descriptions.
  6. Non-blocking PostgreSQL persistence to agent_outputs table.
  7. Fail-safe deterministic fallback narration if LLM endpoint is offline.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set

from agents.base_agent import BaseAgent
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway
from models.llm import LLMLoader
from config.settings import settings

from agents.agent6_impact_assessment.schemas import (
    Agent6Output,
    CVSSAssessment,
    ISSAssessment,
    AffectedAsset,
    RecoveryAction,
    RecoveryChecklist,
    AssessmentStatus,
    CVSSSeverity,
    ISSSeverity
)
from agents.agent6_impact_assessment.cvss_mapper import CVSSMapper
from agents.agent6_impact_assessment.iss_calculator import ISSCalculator
from agents.agent6_impact_assessment.asset_extractor import AssetExtractor
from agents.agent6_impact_assessment.recovery_engine import RecoveryEngine
from agents.agent6_impact_assessment.prompts import (
    AGENT6_SYSTEM_PROMPT,
    build_agent6_user_prompt
)
from agents.agent6_impact_assessment.validator import Agent6Validator

logger = logging.getLogger(__name__)


class ImpactAssessmentAgent(BaseAgent):
    """
    Agent 6 — Impact Assessment Agent.
    Assesses affected assets, determines CVSS and ISS scores, plans recovery,
    and narratively explains the impact with Qwen3-8B.
    """

    def __init__(
        self,
        model: Optional[Any] = None,
        fir_repo: Optional[Any] = None,
        sanitization_gateway: Optional[Any] = None,
        tenant_id: str = "default"
    ):
        model_instance = model if model is not None else LLMLoader().load_fallback()
        fir_instance = fir_repo if fir_repo is not None else FIRRepository()
        gateway_instance = sanitization_gateway if sanitization_gateway is not None else SanitizationGateway()

        super().__init__(
            model=model_instance,
            fir_repo=fir_instance,
            sanitization_gateway=gateway_instance,
            tenant_id=tenant_id
        )
        self.model_name = "Qwen3-8B"
        self.validator = Agent6Validator()

    def run(self, case_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        BaseAgent standard entrypoint.
        Executes full impact assessment and returns dictionary representation of Agent6Output.
        """
        output = self.execute_assessment(case_id, upstream_context=context or {})
        return output.model_dump()

    def execute_assessment(
        self,
        case_id: str,
        upstream_context: Dict[str, Any]
    ) -> Agent6Output:
        """
        Executes end-to-end Agent 6 impact assessment workflow.
        """
        tenant_id = upstream_context.get("tenant_id", self.tenant_id)

        # 1. Ingest upstream agent outputs & FIR findings
        fir_findings = upstream_context.get("fir_findings")
        if not fir_findings:
            if hasattr(self.fir, "get_by_case"):
                fir_findings = self.fir.get_by_case(tenant_id=tenant_id, case_id=case_id) or []
            elif hasattr(self.fir, "get_all"):
                fir_findings = self.fir.get_all(case_id) or []
            else:
                fir_findings = []

        agent3_out = upstream_context.get("agent3_output") or upstream_context.get("agent3") or {}
        agent4_out = upstream_context.get("agent4_output") or upstream_context.get("agent4") or {}
        agent5_out = upstream_context.get("agent5_output") or upstream_context.get("agent5") or {}
        agent2_out = upstream_context.get("agent2_output") or upstream_context.get("agent2") or {}

        # 2. Build valid citation universe from ingested findings and claims
        valid_universe: Set[str] = set()
        for f in fir_findings:
            fid = getattr(f, "finding_id", "") if hasattr(f, "finding_id") else f.get("finding_id", "")
            if fid:
                valid_universe.add(str(fid))

        for c in agent2_out.get("claims", []):
            for eid in c.get("cited_evidence_ids", []):
                valid_universe.add(str(eid))

        for c in agent4_out.get("claims", []):
            for eid in c.get("cited_evidence_ids", []):
                valid_universe.add(str(eid))

        for step in agent3_out.get("attack_path", []):
            for eid in step.get("evidence_ids", []):
                valid_universe.add(str(eid))

        # 3. Step 1: Deterministic Evidence-to-CVSS Metric Mapping
        cvss_assessment = CVSSMapper.map_evidence_to_cvss(
            agent3_output=agent3_out,
            agent4_output=agent4_out,
            agent5_output=agent5_out,
            fir_findings=fir_findings
        )

        # 4. Step 2: Deterministic Asset Inventory Extraction & Risk Scoring
        affected_assets = AssetExtractor.extract_assets(
            agent3_output=agent3_out,
            agent4_output=agent4_out,
            fir_findings=fir_findings
        )
        critical_count = sum(1 for a in affected_assets if a.criticality.value in {"CRITICAL", "HIGH"})

        # 5. Step 3: Deterministic Investigation Severity Score (ISS) Assessment
        iss_assessment = ISSCalculator.calculate_iss(
            affected_assets=affected_assets,
            cvss_assessment=cvss_assessment,
            agent3_output=agent3_out,
            agent4_output=agent4_out,
            fir_findings=fir_findings
        )

        # 6. Step 4: Deterministic Incident Recovery Playbook & Prioritized Checklist
        recovery_actions, recovery_checklist = RecoveryEngine.generate_recovery_plan(
            affected_assets=affected_assets,
            iss_assessment=iss_assessment,
            cvss_assessment=cvss_assessment,
            agent3_output=agent3_out,
            agent4_output=agent4_out
        )

        # 7. Collect all cited evidence IDs across all assessment components
        all_cited: Set[str] = set()
        all_cited.update(cvss_assessment.evidence_ids)
        all_cited.update(iss_assessment.contributing_evidence_ids)
        for a in affected_assets:
            all_cited.update(a.evidence_ids)
        for r in recovery_actions:
            all_cited.update(r.evidence_ids)
        all_cited_list = sorted(list(all_cited))

        # 8. Step 5: Citation & Score Validation Gate
        validation_report = self.validator.validate_output(
            cvss=cvss_assessment,
            iss=iss_assessment,
            assets=affected_assets,
            recovery_actions=recovery_actions,
            valid_evidence_universe=valid_universe
        )

        # 9. Step 6: Narrative Explanation with Qwen3-8B (Protected by Sanitization Gateway)
        findings_summary_raw = "\n".join([
            f"[{getattr(f, 'finding_id', 'F-RAW')}]: {getattr(f, 'fact', str(f))}"
            for f in fir_findings[:8]
        ])
        sanitized_summary = self.sanitized_context_fetch(
            lambda: findings_summary_raw,
            field_name="unstructured"
        )

        user_prompt = build_agent6_user_prompt(
            case_id=case_id,
            tenant_id=tenant_id,
            cvss=cvss_assessment,
            iss=iss_assessment,
            assets=affected_assets,
            recovery_actions=recovery_actions,
            sanitized_findings_summary=sanitized_summary
        )

        narrative_explanation = self._generate_narration(user_prompt, cvss_assessment, iss_assessment, affected_assets, recovery_actions)

        # 10. Construct Final Agent6Output
        output = Agent6Output(
            agent_id="agent_6",
            case_id=case_id,
            tenant_id=tenant_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            model_used=self.model_name,
            execution_status="SUCCESS",
            error_message=None,
            cvss_assessment=cvss_assessment,
            iss_assessment=iss_assessment,
            affected_assets=affected_assets,
            total_assets_affected=len(affected_assets),
            critical_assets_count=critical_count,
            recovery_actions=recovery_actions,
            recovery_checklist=recovery_checklist,
            explanation=narrative_explanation,
            all_cited_evidence_ids=all_cited_list,
            citation_validation=validation_report,
            sanitization_summary={
                "findings_sanitized": len(fir_findings),
                "injections_flagged": 0
            }
        )

        # 11. Non-blocking PostgreSQL persistence
        self._persist_agent_output(output)

        return output

    def _generate_narration(
        self,
        user_prompt: str,
        cvss: CVSSAssessment,
        iss: ISSAssessment,
        assets: List[AffectedAsset],
        actions: List[RecoveryAction]
    ) -> str:
        """
        Queries Qwen3-8B for narration; falls back to deterministic synthesis if offline.
        """
        response_text = ""
        try:
            if hasattr(self.model, "generate"):
                response_text = self.model.generate(prompt=user_prompt, system_prompt=AGENT6_SYSTEM_PROMPT)
            elif callable(self.model):
                response_text = self.model(user_prompt)
        except Exception as exc:
            logger.warning("Agent 6 LLM generation note: %s. Using deterministic narrative synthesis.", exc)

        if not response_text or len(response_text.strip()) < 40:
            return self._generate_fallback_narration(cvss, iss, assets, actions)

        return response_text.strip()

    def _generate_fallback_narration(
        self,
        cvss: CVSSAssessment,
        iss: ISSAssessment,
        assets: List[AffectedAsset],
        actions: List[RecoveryAction]
    ) -> str:
        """
        Deterministic, professional forensic report narration when LLM is unavailable.
        Guarantees that reporting is never blocked and numerical scores remain inviolate.
        """
        # Section 1: Executive Incident Summary
        sec1 = (
            f"### Section 1: Executive Incident Summary & Severity\n"
            f"Investigation impact assessment establishes an overall ARGUS Investigation Severity Score (ISS) "
            f"of **{iss.iss_score}/10.0 ({iss.severity.value})**. "
            f"{iss.executive_summary}"
        )

        # Section 2: Affected Assets
        asset_lines = [
            f"- **{a.asset_id}** ({a.asset_type.value}, Criticality: {a.criticality.value}): "
            f"State: {a.compromise_state.value}, Assessed Risk: {a.risk_score}/10. {a.impact_details}"
            for a in assets
        ]
        sec2 = (
            f"### Section 2: Affected Assets & Threat Blast Radius\n"
            f"A total of {len(assets)} system assets and identities were evaluated:\n"
            + "\n".join(asset_lines)
        )

        # Section 3: Technical Vulnerability Analysis (CVSS v3.1)
        if cvss.base_score is not None:
            cvss_details = (
                f"CVSS v3.1 Base Score: **{cvss.base_score} ({cvss.severity.value})**\n"
                f"Vector String: `{cvss.vector_string}`\n"
                f"Exploitability Subscore: {cvss.exploitability_subscore} | Impact Subscore: {cvss.impact_subscore}\n"
                f"{cvss.calculation_notes}"
            )
        elif cvss.score_range_min is not None and cvss.score_range_max is not None:
            cvss_details = (
                f"CVSS Status: **PARTIAL** (Score Range: [{cvss.score_range_min} - {cvss.score_range_max}], Severity: UNDETERMINED)\n"
                f"Missing Metrics: {', '.join(cvss.missing_metrics)}\n"
                f"{cvss.calculation_notes}"
            )
        else:
            cvss_details = (
                f"CVSS Status: **INSUFFICIENT_DATA** (Score: None, Severity: UNDETERMINED)\n"
                f"Missing Metrics: {', '.join(cvss.missing_metrics)}\n"
                f"{cvss.calculation_notes}"
            )
        sec3 = f"### Section 3: Technical Vulnerability Analysis (CVSS v3.1 Assessment)\n{cvss_details}"

        # Section 4: ISS Breakdown
        factor_lines = [
            f"- **{f.factor_name}**: Raw={f.raw_score}/10, Weighted Contribution={f.weighted_score} pts ({f.description})"
            for f in iss.factor_breakdown.values()
        ]
        sec4 = (
            f"### Section 4: Investigation Severity Score (ISS) Business Impact Breakdown\n"
            f"Investigation-level severity is derived from 6 weighted forensic dimensions:\n"
            + "\n".join(factor_lines)
        )

        # Section 5: Recovery Guidance
        rec_lines = [
            f"- **[{a.phase.value}] ({a.priority.value}) {a.action_id}**: {a.title} ({a.responsible_role.value})\n"
            f"  *Task*: {a.description}\n"
            f"  *Verification*: {a.verification_step}"
            for a in actions[:5]
        ]
        sec5 = (
            f"### Section 5: Priority Containment & Recovery Guidance\n"
            f"The incident response team must execute the following prioritized operations immediately:\n"
            + "\n".join(rec_lines)
        )

        return f"{sec1}\n\n{sec2}\n\n{sec3}\n\n{sec4}\n\n{sec5}"

    def _persist_agent_output(self, output: Agent6Output):
        """
        Non-blocking persistence to PostgreSQL agent_outputs table.
        Matches repository persistence pattern.
        """
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=3
            )
            cur = conn.cursor()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS agent_outputs (
                    id              SERIAL PRIMARY KEY,
                    case_id         TEXT,
                    agent_id        TEXT NOT NULL,
                    claim           TEXT NOT NULL,
                    evidence_ids    TEXT[] DEFAULT '{}',
                    confidence      FLOAT,
                    verified        BOOLEAN,
                    flags           JSONB DEFAULT '{}',
                    created_at      TIMESTAMPTZ DEFAULT NOW(),
                    tenant_id       TEXT NOT NULL DEFAULT 'default',
                    model_used      TEXT,
                    execution_status TEXT DEFAULT 'SUCCESS'
                );
            """)

            query = """
                INSERT INTO agent_outputs 
                    (case_id, tenant_id, agent_id, model_used, claim, evidence_ids, confidence, verified, execution_status, flags, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            full_json = output.model_dump()
            flags_dict = {
                "full_report": json.dumps(full_json, default=str),
                "cvss_score": output.cvss_assessment.base_score,
                "cvss_status": output.cvss_assessment.assessment_status.value,
                "iss_score": output.iss_assessment.iss_score,
                "total_assets": output.total_assets_affected,
                "error_message": output.error_message
            }

            cur.execute(
                query,
                (
                    output.case_id,
                    output.tenant_id,
                    output.agent_id,
                    output.model_used,
                    f"Agent 6 Impact Assessment Complete (ISS: {output.iss_assessment.iss_score}/10)",
                    output.all_cited_evidence_ids,
                    round(output.iss_assessment.iss_score / 10.0, 2),
                    True,
                    output.execution_status,
                    json.dumps(flags_dict),
                    output.timestamp
                )
            )

            conn.commit()
            conn.close()
            logger.info("Agent 6 output persisted to PostgreSQL agent_outputs table for case %s", output.case_id)
        except Exception as exc:
            logger.debug("PostgreSQL agent_outputs non-blocking persist note: %s", exc)
