"""
Agent 1 — Evidence Intelligence Agent
======================================
First reasoning layer over sanitized forensic findings.
Model: Qwen3-8B (Required primary reasoning model)
RAG: No

Flow:
  FIR Findings -> Evidence Sanitization Gateway -> Qwen3-8B Reasoning -> Deterministic Validation Gate -> PostgreSQL Persistence
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from agents.base_agent import BaseAgent
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway, SanitizedAgentContext
from models.llm import LLMLoader
from config.settings import settings

from agents.agent1_evidence_intelligence.schemas import Agent1Claim, Agent1Output, Agent1Input
from agents.agent1_evidence_intelligence.prompts import AGENT1_SYSTEM_PROMPT, build_agent1_user_prompt
from agents.agent1_evidence_intelligence.validator import Agent1Validator

logger = logging.getLogger(__name__)


class EvidenceIntelligenceAgent(BaseAgent):
    """
    Agent 1 — Evidence Intelligence Agent.
    Consumes sanitized FIR findings, reasons over them using Qwen3-8B, and produces
    deterministically validated forensic claims.
    """

    def __init__(
        self,
        model: Optional[Any] = None,
        fir_repo: Optional[Any] = None,
        sanitization_gateway: Optional[Any] = None,
        tenant_id: str = "default"
    ):
        model_instance = model if model is not None else LLMLoader().load_qwen3_8b()
        fir_instance = fir_repo if fir_repo is not None else FIRRepository()
        gateway_instance = sanitization_gateway if sanitization_gateway is not None else SanitizationGateway()
        
        super().__init__(
            model=model_instance,
            fir_repo=fir_instance,
            sanitization_gateway=gateway_instance,
            tenant_id=tenant_id
        )
        self.validator = Agent1Validator()
        self.model_name = "Qwen3-8B"

    def run(self, case_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes Agent 1 analysis over sanitized FIR findings for the given case_id.
        """
        context = context or {}
        tenant_id = context.get("tenant_id", self.tenant_id)
        
        # ── 1. Fetch & Sanitize FIR Findings ───────────────────────────────
        fir_findings = context.get("fir_findings")
        if not fir_findings:
            if hasattr(self.fir, "get_by_case"):
                fir_findings = self.fir.get_by_case(tenant_id=tenant_id, case_id=case_id)
            elif hasattr(self.fir, "get_all"):
                fir_findings = self.fir.get_all(case_id)
            else:
                fir_findings = []

        if not fir_findings:
            logger.warning("Agent 1: No FIR findings found for case_id=%s", case_id)
            output = Agent1Output(
                case_id=case_id,
                tenant_id=tenant_id,
                model_used=self.model_name,
                claims=[],
                total_findings_processed=0,
                sanitization_summary={"findings_sanitized": 0},
                execution_status="FAILED",
                error_message=f"No FIR findings found for case {case_id}"
            )
            return output.model_dump()

        # ── 2. Pass findings through Evidence Sanitization Gateway ──────────
        sanitized_contexts: List[SanitizedAgentContext] = []
        for finding in fir_findings:
            if isinstance(finding, SanitizedAgentContext):
                sanitized_contexts.append(finding)
            else:
                sanitized_ctx = self.gateway.sanitize_finding(finding)
                sanitized_contexts.append(sanitized_ctx)

        # Build XML evidence blocks for LLM prompt
        xml_blocks = "\n".join(ctx.xml_evidence_block for ctx in sanitized_contexts)

        # ── 3. Construct Prompt & Invoke Qwen3-8B ───────────────────────────
        user_prompt = build_agent1_user_prompt(case_id, xml_blocks)
        
        try:
            if hasattr(self.model, "generate"):
                llm_response = self.model.generate(user_prompt, system_prompt=AGENT1_SYSTEM_PROMPT)
            elif callable(self.model):
                llm_response = self.model(user_prompt)
            else:
                raise RuntimeError("Provided model instance lacks callable or generate method.")
        except Exception as exc:
            logger.error("Agent 1: Qwen3-8B invocation failed: %s", exc)
            output = Agent1Output(
                case_id=case_id,
                tenant_id=tenant_id,
                model_used=self.model_name,
                claims=[],
                total_findings_processed=len(fir_findings),
                sanitization_summary={"findings_sanitized": len(sanitized_contexts)},
                execution_status="FAILED",
                error_message=f"LLM invocation error: {str(exc)}"
            )
            return output.model_dump()

        # ── 4. Parse Structured JSON Response ──────────────────────────────
        raw_claims = self._parse_json_claims(llm_response)

        # ── 5. Deterministic Validation Gate ───────────────────────────────
        valid_finding_ids, valid_lineage_ids = self.validator.extract_valid_id_universe(fir_findings)
        validated_claims = self.validator.validate_claims(
            claims=raw_claims,
            valid_finding_ids=valid_finding_ids,
            valid_lineage_ids=valid_lineage_ids
        )

        status = "SUCCESS" if validated_claims else "PARTIAL_SUCCESS"

        output = Agent1Output(
            case_id=case_id,
            tenant_id=tenant_id,
            model_used=self.model_name,
            timestamp=datetime.now(timezone.utc),
            claims=validated_claims,
            total_findings_processed=len(fir_findings),
            sanitization_summary={
                "findings_sanitized": len(sanitized_contexts),
                "injections_flagged": sum(1 for c in sanitized_contexts if c.injection_flagged)
            },
            execution_status=status
        )

        # ── 6. Persist structured output to PostgreSQL ─────────────────────
        self._persist_agent_output(output)

        return output.model_dump()

    def _parse_json_claims(self, raw_text: str) -> List[Agent1Claim]:
        """
        Extracts JSON from LLM output string and constructs Agent1Claim objects.
        """
        if not raw_text:
            return []

        cleaned = raw_text.strip()
        # Handle markdown code fences
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(cleaned)
        except Exception as err:
            logger.warning("Failed to parse LLM response as JSON: %s. Raw text: %s", err, raw_text[:200])
            # Construct a safe fallback claim capturing raw text
            return [
                Agent1Claim(
                    claim_id="CLM-AG1-FALLBACK-001",
                    summary="Raw unparsed model reasoning",
                    findings_summary=raw_text[:500],
                    cited_evidence_ids=[],
                    assessed_importance="informational",
                    confidence_score=0.5,
                    reasoning_notes="JSON parsing failed; returned raw text in fallback claim."
                )
            ]

        claims_list = data.get("claims", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        parsed_claims: List[Agent1Claim] = []

        for idx, item in enumerate(claims_list):
            if isinstance(item, dict):
                cid = item.get("claim_id") or f"CLM-AG1-{idx+1:03d}"
                summary = item.get("summary") or "Forensic Interpretation"
                findings_summary = item.get("findings_summary") or summary
                cited_ids = item.get("cited_evidence_ids") or item.get("evidence_ids") or []
                if isinstance(cited_ids, str):
                    cited_ids = [c.strip() for c in cited_ids.split(",") if c.strip()]

                importance = item.get("assessed_importance", "medium")
                if importance not in ("critical", "high", "medium", "low", "informational"):
                    importance = "medium"

                conf = item.get("confidence_score")
                if conf is None:
                    conf = item.get("confidence", 0.8)
                try:
                    conf = float(conf)
                except (ValueError, TypeError):
                    conf = -1.0  # Invalid indicator for validator

                claim_obj = Agent1Claim(
                    claim_id=cid,
                    summary=summary,
                    findings_summary=findings_summary,
                    cited_evidence_ids=cited_ids,
                    assessed_importance=importance,
                    confidence_score=conf,
                    missing_evidence_noted=item.get("missing_evidence_noted", []),
                    uncertainties_or_conflicts=item.get("uncertainties_or_conflicts", []),
                    reasoning_notes=item.get("reasoning_notes", "")
                )
                parsed_claims.append(claim_obj)

        return parsed_claims

    def _persist_agent_output(self, output: Agent1Output):
        """
        Optionally persists structured agent output into PostgreSQL `agent_outputs` table.
        """
        try:
            from databases.postgres_client import postgres
            if postgres._pool is not None:
                import asyncio
                query = """
                    INSERT INTO agent_outputs (case_id, agent_id, claim, evidence_ids, confidence, verified, flags)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                """
                for claim in output.claims:
                    flags_dict = {
                        "invalid_citations": claim.invalid_citations,
                        "raw_model_confidence": claim.raw_model_confidence,
                        "validation_notes": claim.validation_notes,
                        "is_valid_confidence": claim.is_valid_confidence
                    }
                    asyncio.create_task(
                        postgres.execute(
                            query,
                            output.case_id,
                            output.agent_id,
                            claim.summary,
                            claim.cited_evidence_ids,
                            claim.confidence_score,
                            claim.citation_verified,
                            json.dumps(flags_dict)
                        )
                    )
        except Exception as exc:
            logger.debug("PostgreSQL async persist skipped/deferred: %s", exc)
