"""
Agent 3 — Attack Reconstruction Agent
======================================
Second reasoning layer over sanitized forensic findings.
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

from agents.agent3_attack_reconstruction.schemas import (
    Agent3Output, InfectionPath, AttackTimelineEvent, AttackChainStage,
    LateralMovement, MissingExpectedEvent
)
from agents.agent3_attack_reconstruction.prompts import AGENT3_SYSTEM_PROMPT, build_agent3_user_prompt
from agents.agent3_attack_reconstruction.validator import Agent3Validator

logger = logging.getLogger(__name__)

class AttackReconstructionAgent(BaseAgent):
    """
    Agent 3 — Attack Reconstruction Agent.
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
        self.validator = Agent3Validator()
        self.model_name = "Qwen3-8B"

    def run(self, case_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes Agent 3 analysis over sanitized FIR findings for the given case_id.
        """
        context = context or {}
        tenant_id = context.get("tenant_id", self.tenant_id)
        
        fir_findings = context.get("fir_findings")
        if not fir_findings:
            if hasattr(self.fir, "get_by_case"):  # self.exists fir check
                fir_findings = self.sanitized_context_fetch(self.fir.get_by_case, tenant_id=tenant_id, case_id=case_id)
            elif hasattr(self.fir, "get_all"):  # self.exists fir check
                fir_findings = self.sanitized_context_fetch(self.fir.get_all, case_id)
            else:
                fir_findings = []

        if not fir_findings:
            logger.warning("Agent 3: No FIR findings found for case_id=%s", case_id)
            output = Agent3Output(
                agent_id="agent_3",
                model_used=self.model_name,
                total_findings_processed=0,
                sanitization_summary={},
                case_id=case_id,
                tenant_id=tenant_id,
                infection_path=InfectionPath(entry_point="No evidence", evidence_ids=[], confidence=0.0),
                attack_timeline=[],
                attack_chain=[],
                lateral_movement=[],
                missing_expected_events=[],
                reconstruction_summary="",
                overall_confidence=0.0,
                execution_status="FAILED",
                error_message=f"No FIR findings found for case {case_id}"
            )
            from agents.agent3_attack_reconstruction.report import Agent3ReportGenerator
            output.investigator_report = Agent3ReportGenerator.generate(output)
            return output.model_dump()

        sanitized_contexts: List[SanitizedAgentContext] = []
        for finding in fir_findings:
            if isinstance(finding, SanitizedAgentContext):
                sanitized_contexts.append(finding)
            else:
                sanitized_ctx = self.gateway.sanitize_finding(finding)
                sanitized_contexts.append(sanitized_ctx)

        xml_blocks = "\n".join(ctx.xml_evidence_block for ctx in sanitized_contexts)

        correlation_data = context.get("agent2_correlation", "")
        neo4j_client = context.get("neo4j_client")
        
        candidate_paths = ""
        if neo4j_client:
            try:
                candidate_paths = self.sanitized_context_fetch(
                    neo4j_client.query,
                    "MATCH p=(:Event)-[:NEXT_EVENT*]->(:Event) WHERE p.case_id = $case_id RETURN p LIMIT 50",
                    field_name="unstructured",
                    case_id=case_id
                )
            except Exception as e:
                candidate_paths = f"Could not retrieve candidate paths: {e}"

        user_prompt = build_agent3_user_prompt(
            case_id, 
            xml_blocks, 
            correlation_data=json.dumps(correlation_data) if correlation_data else "", 
            candidate_paths=candidate_paths
        )
        
        try:
            if hasattr(self.model, "generate"):
                llm_response = self.model.generate(user_prompt, system_prompt=AGENT3_SYSTEM_PROMPT)
            elif callable(self.model):
                llm_response = self.model(user_prompt)
            else:
                raise RuntimeError("Provided model instance lacks callable or generate method.")
        except Exception as exc:
            logger.error("Agent 3: Qwen3-8B invocation failed: %s", exc)
            output = Agent3Output(
                agent_id="agent_3",
                model_used=self.model_name,
                total_findings_processed=0,
                sanitization_summary={},
                case_id=case_id,
                tenant_id=tenant_id,
                infection_path=InfectionPath(entry_point="Error", evidence_ids=[], confidence=0.0),
                attack_timeline=[],
                attack_chain=[],
                lateral_movement=[],
                missing_expected_events=[],
                reconstruction_summary="",
                overall_confidence=0.0,
                execution_status="FAILED",
                error_message=f"LLM invocation error: {str(exc)}"
            )
            from agents.agent3_attack_reconstruction.report import Agent3ReportGenerator
            output.investigator_report = Agent3ReportGenerator.generate(output)
            return output.model_dump()

        output = self._parse_json_to_output(llm_response, case_id, tenant_id)

        valid_finding_ids, valid_lineage_ids = self.validator.extract_valid_id_universe(fir_findings)
        output = self.validator.validate_output(output, valid_finding_ids, valid_lineage_ids)

        output.total_findings_processed = len(fir_findings)
        output.sanitization_summary = {
            "findings_sanitized": len(sanitized_contexts),
            "injections_flagged": sum(1 for c in sanitized_contexts if c.injection_flagged)
        }

        # Generate Human-Readable Investigator-Facing Report
        from agents.agent3_attack_reconstruction.report import Agent3ReportGenerator
        output.investigator_report = Agent3ReportGenerator.generate(output)

        self._persist_agent_output(output)

        return output.model_dump()

    def _parse_json_to_output(self, raw_text: str, case_id: str, tenant_id: str) -> Agent3Output:
        if not raw_text:
            return Agent3Output(
                agent_id="agent_3",
                model_used=self.model_name,
                total_findings_processed=0,
                sanitization_summary={},
                case_id=case_id, tenant_id=tenant_id,
                infection_path=InfectionPath(entry_point="Parse Error", evidence_ids=[], confidence=0.0),
                attack_timeline=[],
                attack_chain=[],
                lateral_movement=[],
                missing_expected_events=[],
                reconstruction_summary="",
                overall_confidence=0.0,
                execution_status="FAILED", error_message="Empty LLM response"
            )

        cleaned = raw_text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(cleaned)
        except Exception as err:
            logger.warning("Failed to parse LLM response as JSON: %s. Raw text: %s", err, raw_text[:200])
            return Agent3Output(
                agent_id="agent_3",
                model_used=self.model_name,
                total_findings_processed=0,
                sanitization_summary={},
                case_id=case_id, tenant_id=tenant_id,
                infection_path=InfectionPath(entry_point="Parse Error", evidence_ids=[], confidence=0.0),
                attack_timeline=[],
                attack_chain=[],
                lateral_movement=[],
                missing_expected_events=[],
                reconstruction_summary="",
                overall_confidence=0.0,
                execution_status="FAILED", error_message=f"JSON Parse Error: {err}"
            )

        try:
            return Agent3Output(
                agent_id="agent_3",
                execution_status="SUCCESS",
                error_message=None,
                total_findings_processed=0,
                sanitization_summary={},
                case_id=case_id,
                tenant_id=tenant_id,
                infection_path=InfectionPath(**data.get("infection_path", {"entry_point": "Unknown", "evidence_ids": [], "confidence": 0.0})),
                attack_timeline=[AttackTimelineEvent(**x) for x in data.get("attack_timeline", [])],
                attack_chain=[AttackChainStage(**x) for x in data.get("attack_chain", [])],
                lateral_movement=[LateralMovement(**x) for x in data.get("lateral_movement", [])],
                missing_expected_events=[MissingExpectedEvent(**x) for x in data.get("missing_expected_events", [])],
                reconstruction_summary=data.get("reconstruction_summary", ""),
                overall_confidence=float(data.get("overall_confidence", 0.0))
            )
        except Exception as err:
            return Agent3Output(
                agent_id="agent_3",
                model_used=self.model_name,
                total_findings_processed=0,
                sanitization_summary={},
                case_id=case_id, tenant_id=tenant_id,
                infection_path=InfectionPath(entry_point="Schema Error", evidence_ids=[], confidence=0.0),
                attack_timeline=[],
                attack_chain=[],
                lateral_movement=[],
                missing_expected_events=[],
                reconstruction_summary="",
                overall_confidence=0.0,
                execution_status="FAILED", error_message=f"Schema Match Error: {err}"
            )

    def _persist_agent_output(self, output: Agent3Output):
        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=5
            )
            cur = conn.cursor()
            
            # Idempotent table column migration check
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
                ALTER TABLE agent_outputs DROP CONSTRAINT IF EXISTS agent_outputs_case_id_fkey;
                ALTER TABLE agent_outputs ALTER COLUMN case_id TYPE TEXT USING case_id::text;
                ALTER TABLE agent_outputs ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
                ALTER TABLE agent_outputs ADD COLUMN IF NOT EXISTS model_used TEXT;
                ALTER TABLE agent_outputs ADD COLUMN IF NOT EXISTS execution_status TEXT DEFAULT 'SUCCESS';
            """)

            query = """
                INSERT INTO agent_outputs 
                    (case_id, tenant_id, agent_id, model_used, claim, evidence_ids, confidence, verified, execution_status, flags, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            # Save full report in flags with a main summary claim
            full_json = output.model_dump()
            flags_dict = {
                "full_report": json.dumps(full_json, default=str),
                "error_message": output.error_message
            }
            
            cur.execute(
                query,
                (
                    output.case_id,
                    output.tenant_id,
                    output.agent_id,
                    output.model_used,
                    "Agent 3 Attack Reconstruction Complete",
                    [],
                    output.overall_confidence,
                    True,
                    output.execution_status,
                    json.dumps(flags_dict),
                    output.timestamp
                )
            )
            
            conn.commit()
            conn.close()
            logger.info("Agent 3 output persisted to PostgreSQL agent_outputs table for case %s", output.case_id)
        except Exception as exc:
            logger.warning("PostgreSQL agent_outputs persist error: %s", exc)
