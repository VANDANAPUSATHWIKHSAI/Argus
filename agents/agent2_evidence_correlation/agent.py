"""
Agent 2 — Evidence Correlation Agent
======================================
Second reasoning layer over sanitized forensic findings.
Answers: "Which pieces of evidence are related?"
Model: Qwen3-8B
RAG: No
Tools: Neo4j / GDS / Timeline Builder / Graph Engine / Conflict Detector

Flow:
  FIR Findings -> Deterministic Timeline & Graph Construction & Conflict Detection 
               -> Evidence Sanitization Gateway 
               -> Qwen3-8B Narration 
               -> Deterministic Validation Gate 
               -> PostgreSQL Persistence
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

from agents.agent2_evidence_correlation.schemas import (
    Agent2Claim, Agent2Output, Agent2Input, Agent2CorrelationSignal
)
from agents.agent2_evidence_correlation.timeline import TimelineBuilder
from agents.agent2_evidence_correlation.graph_builder import GraphBuilder
from agents.agent2_evidence_correlation.conflict_detector import ConflictDetector
from agents.agent2_evidence_correlation.prompts import AGENT2_SYSTEM_PROMPT, build_agent2_user_prompt
from agents.agent2_evidence_correlation.validator import Agent2Validator

logger = logging.getLogger(__name__)


class EvidenceCorrelationAgent(BaseAgent):
    """
    Agent 2 — Evidence Correlation Agent.
    Executes deterministic timeline clustering, graph community detection, and conflict detection,
    sanitizes context, invokes Qwen3-8B for narration, validates citations, and persists results.
    """

    def __init__(
        self,
        model: Optional[Any] = None,
        fir_repo: Optional[Any] = None,
        sanitization_gateway: Optional[Any] = None,
        neo4j_client: Optional[Any] = None,
        tenant_id: str = "default",
        time_window_seconds: float = 3600.0
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

        self.neo4j_client = neo4j_client
        self.timeline_builder = TimelineBuilder(time_window_seconds=time_window_seconds)
        self.graph_builder = GraphBuilder(neo4j_client=neo4j_client)
        self.conflict_detector = ConflictDetector()
        self.validator = Agent2Validator()
        self.model_name = "Qwen3-8B"

    def run(self, case_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes Agent 2 analysis over sanitized FIR findings for the given case_id.
        """
        context = context or {}
        tenant_id = context.get("tenant_id", self.tenant_id)
        neo4j_client = context.get("neo4j_client", self.neo4j_client)

        if neo4j_client and neo4j_client != self.graph_builder.neo4j_client:
            self.graph_builder.neo4j_client = neo4j_client

        # ── 1. Fetch FIR Findings ──────────────────────────────────────────
        fir_findings = context.get("fir_findings")
        if not fir_findings:
            if hasattr(self.fir, "get_by_case"):
                fir_findings = self.fir.get_by_case(tenant_id=tenant_id, case_id=case_id)
            elif hasattr(self.fir, "get_all"):
                fir_findings = self.fir.get_all(case_id)
            else:
                fir_findings = []

        if not fir_findings:
            logger.warning("Agent 2: No FIR findings found for case_id=%s", case_id)
            output = Agent2Output(
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

        # ── 3. Deterministic Foundations (Timeline, Graph, Conflicts) ─────
        sorted_findings, timeline_clusters = self.timeline_builder.build_timeline(fir_findings)
        communities, graph_metrics = self.graph_builder.build_graph_and_communities(case_id, fir_findings)
        conflicts = self.conflict_detector.detect_conflicts(fir_findings)

        signals = Agent2CorrelationSignal(
            temporal_clusters=timeline_clusters,
            graph_communities=communities,
            conflicts=conflicts,
            total_nodes=graph_metrics.get("total_nodes", 0),
            total_edges=graph_metrics.get("total_edges", 0),
            total_communities=graph_metrics.get("total_communities", 0)
        )

        # Build XML payload incorporating deterministic signals & sanitized context
        evidence_blocks = "\n".join(ctx.xml_evidence_block for ctx in sanitized_contexts)
        signals_xml = (
            f"<deterministic_correlation_signals>\n"
            f"<graph_metrics nodes='{signals.total_nodes}' edges='{signals.total_edges}' communities='{signals.total_communities}'/>\n"
            f"<timeline_clusters count='{len(signals.temporal_clusters)}'>\n"
            f"{json.dumps([c.model_dump(mode='json') for c in signals.temporal_clusters], default=str)}\n"
            f"</timeline_clusters>\n"
            f"<graph_communities count='{len(signals.graph_communities)}'>\n"
            f"{json.dumps([g.model_dump(mode='json') for g in signals.graph_communities], default=str)}\n"
            f"</graph_communities>\n"
            f"<detected_conflicts count='{len(signals.conflicts)}'>\n"
            f"{json.dumps([cf.model_dump(mode='json') for cf in signals.conflicts], default=str)}\n"
            f"</detected_conflicts>\n"
            f"</deterministic_correlation_signals>\n\n"
            f"<sanitized_evidence_findings>\n"
            f"{evidence_blocks}\n"
            f"</sanitized_evidence_findings>"
        )

        # ── 4. Construct Prompt & Invoke Qwen3-8B ───────────────────────────
        user_prompt = build_agent2_user_prompt(case_id, signals_xml)
        
        try:
            if hasattr(self.model, "generate"):
                llm_response = self.model.generate(user_prompt, system_prompt=AGENT2_SYSTEM_PROMPT)
            elif callable(self.model):
                llm_response = self.model(user_prompt)
            else:
                raise RuntimeError("Provided model instance lacks callable or generate method.")
        except Exception as exc:
            logger.error("Agent 2: Qwen3-8B invocation failed: %s", exc)
            output = Agent2Output(
                case_id=case_id,
                tenant_id=tenant_id,
                model_used=self.model_name,
                claims=[],
                total_findings_processed=len(fir_findings),
                graph_metrics=graph_metrics,
                sanitization_summary={"findings_sanitized": len(sanitized_contexts)},
                execution_status="FAILED",
                error_message=f"LLM invocation error: {str(exc)}"
            )
            return output.model_dump()

        # ── 5. Parse Structured JSON Response ──────────────────────────────
        raw_claims = self._parse_json_claims(llm_response)

        # ── 6. Deterministic Validation Gate ───────────────────────────────
        valid_finding_ids, valid_lineage_ids = self.validator.extract_valid_id_universe(fir_findings)
        validated_claims = self.validator.validate_claims(
            claims=raw_claims,
            valid_finding_ids=valid_finding_ids,
            valid_lineage_ids=valid_lineage_ids
        )

        status = "SUCCESS" if validated_claims else "PARTIAL_SUCCESS"

        output = Agent2Output(
            case_id=case_id,
            tenant_id=tenant_id,
            model_used=self.model_name,
            timestamp=datetime.now(timezone.utc),
            claims=validated_claims,
            total_findings_processed=len(fir_findings),
            graph_metrics=graph_metrics,
            sanitization_summary={
                "findings_sanitized": len(sanitized_contexts),
                "injections_flagged": sum(1 for c in sanitized_contexts if c.injection_flagged)
            },
            execution_status=status
        )

        # ── 7. Persist structured output to PostgreSQL ─────────────────────
        self._persist_agent_output(output)

        return output.model_dump()

    def _parse_json_claims(self, raw_text: str) -> List[Agent2Claim]:
        """
        Extracts JSON from LLM output string and constructs Agent2Claim objects.
        """
        if not raw_text:
            return []

        cleaned = raw_text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(cleaned)
        except Exception as err:
            logger.warning("Failed to parse LLM response as JSON: %s. Raw text: %s", err, raw_text[:200])
            return [
                Agent2Claim(
                    claim_id="CLM-AG2-FALLBACK-001",
                    summary="Raw unparsed evidence correlation reasoning",
                    findings_summary=raw_text[:500],
                    cited_evidence_ids=[],
                    correlation_type="multi_signal",
                    assessed_importance="informational",
                    confidence_score=0.5,
                    reasoning_notes="JSON parsing failed; returned raw text in fallback claim."
                )
            ]

        claims_list = data.get("claims", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        parsed_claims: List[Agent2Claim] = []

        for idx, item in enumerate(claims_list):
            if isinstance(item, dict):
                cid = item.get("claim_id") or f"CLM-AG2-{idx+1:03d}"
                summary = item.get("summary") or "Evidence Correlation Claim"
                findings_summary = item.get("findings_summary") or summary
                cited_ids = item.get("cited_evidence_ids") or item.get("evidence_ids") or []
                if isinstance(cited_ids, str):
                    cited_ids = [c.strip() for c in cited_ids.split(",") if c.strip()]

                ctype = item.get("correlation_type", "multi_signal")
                if ctype not in ("temporal", "entity", "shared_artifact", "conflict", "multi_signal"):
                    ctype = "multi_signal"

                importance = item.get("assessed_importance", "medium")
                if importance not in ("critical", "high", "medium", "low", "informational"):
                    importance = "medium"

                conf = item.get("confidence_score")
                if conf is None:
                    conf = item.get("confidence", 0.8)
                try:
                    conf = float(conf)
                except (ValueError, TypeError):
                    conf = -1.0

                claim_obj = Agent2Claim(
                    claim_id=cid,
                    summary=summary,
                    correlation_type=ctype,
                    findings_summary=findings_summary,
                    cited_evidence_ids=cited_ids,
                    community_id=item.get("community_id"),
                    assessed_importance=importance,
                    confidence_score=conf,
                    timeline_sequence=item.get("timeline_sequence", []),
                    conflicts_noted=item.get("conflicts_noted", []),
                    reasoning_notes=item.get("reasoning_notes", "")
                )
                parsed_claims.append(claim_obj)

        return parsed_claims

    def _persist_agent_output(self, output: Agent2Output):
        """
        Persists structured agent output into PostgreSQL `agent_outputs` table.
        """
        try:
            import psycopg2
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=5
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

            items_to_insert = output.claims if output.claims else []
            if not items_to_insert:
                flags_json = json.dumps({
                    "error_message": output.error_message or "No claims produced",
                    "graph_metrics": output.graph_metrics
                })
                cur.execute(
                    query,
                    (
                        output.case_id,
                        output.tenant_id,
                        output.agent_id,
                        output.model_used,
                        output.error_message or "Agent 2 Execution Completed",
                        [],
                        0.0,
                        False,
                        output.execution_status,
                        flags_json,
                        output.timestamp
                    )
                )
            else:
                for claim in items_to_insert:
                    flags_dict = {
                        "invalid_citations": claim.invalid_citations,
                        "raw_model_confidence": claim.raw_model_confidence,
                        "validation_notes": claim.validation_notes,
                        "is_valid_confidence": claim.is_valid_confidence,
                        "correlation_type": claim.correlation_type,
                        "community_id": claim.community_id,
                        "timeline_sequence": claim.timeline_sequence,
                        "conflicts_noted": claim.conflicts_noted,
                        "findings_summary": claim.findings_summary,
                        "reasoning_notes": claim.reasoning_notes,
                        "graph_metrics": output.graph_metrics
                    }
                    cur.execute(
                        query,
                        (
                            output.case_id,
                            output.tenant_id,
                            output.agent_id,
                            output.model_used,
                            claim.summary,
                            claim.cited_evidence_ids,
                            claim.confidence_score,
                            claim.citation_verified,
                            output.execution_status,
                            json.dumps(flags_dict),
                            output.timestamp
                        )
                    )
            conn.commit()
            conn.close()
            logger.info("Agent 2 output persisted to PostgreSQL agent_outputs table for case %s", output.case_id)
        except Exception as exc:
            logger.warning("PostgreSQL agent_outputs persist error: %s", exc)
