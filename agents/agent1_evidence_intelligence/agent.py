"""
Agent 1 — Evidence Intelligence & Triage Agent
================================================
First reasoning layer over sanitized forensic findings.
Performs evidence triage, priority assessment (Investigative Value vs Threat Severity),
clustering, evidence-driven question generation, evidence gap detection, readiness evaluation,
and downstream agent relevance mapping.

Model: Qwen3-8B (Required primary reasoning model)
RAG: No

Flow:
  FIR Findings -> Deterministic Preprocessing -> Evidence Sanitization Gateway
               -> Qwen3-8B Triage -> Deterministic Validation Gate (Evidence Reference Gate)
               -> Idempotent PostgreSQL Persistence
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple

from agents.base_agent import BaseAgent
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway, SanitizedAgentContext
from models.llm import LLMLoader
from config.settings import settings

from agents.agent1_evidence_intelligence.schemas import (
    Agent1Input,
    Agent1Output,
    Agent1Claim,
    Agent1InvestigationReadiness,
    Agent1EvidenceSummary,
    Agent1EvidenceAssessment,
    Agent1SupportingLink,
    Agent1EvidenceCluster,
    Agent1InvestigationQuestion,
    Agent1FocusArea,
    Agent1EvidenceGap
)
from agents.agent1_evidence_intelligence.prompts import (
    AGENT1_SYSTEM_PROMPT,
    AGENT1_PROMPT_VERSION,
    build_agent1_user_prompt
)
from agents.agent1_evidence_intelligence.validator import Agent1Validator

logger = logging.getLogger(__name__)


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


_AGENT_OUTPUTS_TABLE_INITIALIZED = False


def _ensure_agent_outputs_table_initialized(conn):
    global _AGENT_OUTPUTS_TABLE_INITIALIZED
    if _AGENT_OUTPUTS_TABLE_INITIALIZED:
        return
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
        CREATE UNIQUE INDEX IF NOT EXISTS agent_outputs_tenant_case_agent_claim_idx 
        ON agent_outputs (tenant_id, case_id, agent_id, claim);
    """)
    conn.commit()
    _AGENT_OUTPUTS_TABLE_INITIALIZED = True


class EvidenceIntelligenceAgent(BaseAgent):
    """
    Agent 1 — Evidence Intelligence, Triage & Investigation Prioritization Agent.
    Consumes sanitized FIR findings, performs deterministic preprocessing, calls Qwen3-8B,
    validates output via Evidence Reference Gate, and persists structured results.
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
        self.prompt_version = AGENT1_PROMPT_VERSION

    def _compute_deterministic_preprocessing(
        self,
        fir_findings: List[Any],
        case_id: str,
        tenant_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        STEP 4: Objective Metadata Calculation before calling LLM.
        Calculates provenance completeness, duplicate fingerprints, evidence category inventory,
        coverage breakdown, and hard readiness blockers.
        """
        total_findings = len(fir_findings)
        layers_present: Set[str] = set()
        source_tools_present: Set[str] = set()
        provenance_count = 0
        conflicting_count = 0
        fingerprints: Set[str] = set()
        duplicate_count = 0

        inventory: Dict[str, int] = {
            "filesystem": 0,
            "registry": 0,
            "logs": 0,
            "processes": 0,
            "memory": 0,
            "network": 0,
            "browser": 0,
            "email": 0,
            "yara": 0,
            "endpoint": 0,
            "other": 0
        }

        for f in fir_findings:
            lyr = str(_get_val(f, "layer") or "unknown").lower()
            layers_present.add(lyr)

            src_tool = str(_get_val(f, "source_tool") or "").lower()
            if src_tool:
                source_tools_present.add(src_tool)

            fp = _get_val(f, "finding_fingerprint") or _get_val(f, "finding_id")
            if fp:
                if fp in fingerprints:
                    duplicate_count += 1
                else:
                    fingerprints.add(fp)

            ev_ref = _get_val(f, "evidence_reference", [])
            src_art = _get_val(f, "source_artifact_id", None)
            if ev_ref or src_art:
                provenance_count += 1

            if _get_val(f, "injection_flagged", False):
                conflicting_count += 1

            if "registry" in lyr or "reg" in src_tool:
                inventory["registry"] += 1
            elif "process" in lyr or "sysmon" in src_tool:
                inventory["processes"] += 1
            elif "memory" in lyr or "volatility" in src_tool:
                inventory["memory"] += 1
            elif "net" in lyr or "zeek" in src_tool or "pcap" in lyr:
                inventory["network"] += 1
            elif "browser" in lyr or "hindsight" in src_tool:
                inventory["browser"] += 1
            elif "email" in lyr or "eml" in lyr:
                inventory["email"] += 1
            elif "yara" in lyr:
                inventory["yara"] += 1
            elif "file" in lyr or "tsk" in src_tool:
                inventory["filesystem"] += 1
            elif "log" in lyr or "hayabusa" in src_tool or "evtx" in lyr:
                inventory["logs"] += 1
            elif "endpoint" in lyr or "defender" in src_tool:
                inventory["endpoint"] += 1
            else:
                inventory["other"] += 1

        prov_ratio = (provenance_count / total_findings) if total_findings > 0 else 0.0

        readiness_blockers: List[str] = []
        if total_findings == 0:
            readiness_blockers.append("Zero FIR findings available for case")
        if prov_ratio < 0.5 and total_findings > 0:
            readiness_blockers.append("Provenance completeness ratio below 50%")

        coverage: Dict[str, str] = {
            "execution": "HIGH" if (inventory["processes"] > 0 or inventory["logs"] > 0) else "LOW",
            "persistence": "HIGH" if (inventory["registry"] > 0 or inventory["filesystem"] > 0) else "LOW",
            "credential_access": "MEDIUM" if (inventory["memory"] > 0 or inventory["registry"] > 0) else "LOW",
            "discovery": "MEDIUM" if (inventory["processes"] > 0 or inventory["logs"] > 0) else "LOW",
            "network_c2": "HIGH" if inventory["network"] > 0 else "LOW",
            "exfiltration": "MEDIUM" if inventory["network"] > 0 else "LOW",
            "impact": "LOW" if inventory["logs"] == 0 else "MEDIUM",
            "initial_access": "HIGH" if (inventory["email"] > 0 or inventory["browser"] > 0 or inventory["network"] > 0) else "LOW"
        }

        if total_findings == 0:
            readiness_status = "NOT_READY"
            readiness_reason = "No forensic evidence available for case."
        elif readiness_blockers:
            readiness_status = "READY_WITH_LIMITATIONS"
            readiness_reason = f"Evidence available with limitations: {'; '.join(readiness_blockers)}"
        else:
            readiness_status = "READY"
            readiness_reason = f"Ingested {total_findings} FIR findings across {len(layers_present)} forensic layers."

        trust_score = round(min(1.0, max(0.0, prov_ratio * 0.7 + (1.0 - conflicting_count / max(1, total_findings)) * 0.3)), 2)

        return {
            "total_findings": total_findings,
            "unique_fingerprints": len(fingerprints),
            "duplicate_count": duplicate_count,
            "layers_present": sorted(list(layers_present)),
            "source_tools_present": sorted(list(source_tools_present)),
            "provenance_ratio": prov_ratio,
            "conflicting_count": conflicting_count,
            "inventory": inventory,
            "coverage": coverage,
            "readiness_status": readiness_status,
            "readiness_reason": readiness_reason,
            "readiness_blockers": readiness_blockers,
            "trust_score": trust_score,
        }

    def run(self, case_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes Agent 1 analysis over sanitized FIR findings for the given case_id.
        """
        context = context or {}
        tenant_id = context.get("tenant_id", self.tenant_id)

        # ── 1. Fetch FIR Findings ──────────────────────────────────────────
        fir_findings = context.get("fir_findings")
        if not fir_findings:
            if hasattr(self.fir, "get_by_case"):
                fir_findings = self.sanitized_context_fetch(self.fir.get_by_case, tenant_id=tenant_id, case_id=case_id)
            elif hasattr(self.fir, "get_all"):
                fir_findings = self.sanitized_context_fetch(self.fir.get_all, case_id)
            else:
                fir_findings = []

        # Deterministic Preprocessing
        metrics = self._compute_deterministic_preprocessing(fir_findings or [], case_id, tenant_id, context)

        if not fir_findings:
            logger.warning("Agent 1: No FIR findings found for case_id=%s", case_id)
            output = Agent1Output(
                case_id=case_id,
                tenant_id=tenant_id,
                model_used=self.model_name,
                investigation_readiness=Agent1InvestigationReadiness(
                    status="NOT_READY",
                    reason="No FIR findings found for case"
                ),
                evidence_summary=Agent1EvidenceSummary(total_findings=0),
                total_findings_processed=0,
                sanitization_summary={"findings_sanitized": 0},
                evidence_trust_score=0.0,
                evidence_quality_summary=metrics,
                readiness_blockers=metrics["readiness_blockers"],
                execution_status="FAILED",
                failure_type="NO_EVIDENCE",
                error_message=f"No FIR findings found for case {case_id}"
            )
            self._persist_agent_output(output)
            return output.model_dump()

        # ── 2. Pass findings through Evidence Sanitization Gateway ──────────
        sanitized_contexts: List[SanitizedAgentContext] = []
        xml_blocks_list: List[str] = []
        injections_flagged_count = 0

        for finding in fir_findings:
            if isinstance(finding, SanitizedAgentContext):
                sanitized_contexts.append(finding)
                xml_blocks_list.append(finding.xml_evidence_block)
                if finding.injection_flagged:
                    injections_flagged_count += 1
            else:
                sanitized_ctx = self.gateway.sanitize_finding(finding)
                sanitized_contexts.append(sanitized_ctx)
                xml_blocks_list.append(sanitized_ctx.xml_evidence_block)
                if sanitized_ctx.injection_flagged:
                    injections_flagged_count += 1

        xml_blocks = "\n".join(xml_blocks_list)

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
                investigation_readiness=Agent1InvestigationReadiness(
                    status=metrics["readiness_status"],
                    reason=metrics["readiness_reason"]
                ),
                evidence_summary=Agent1EvidenceSummary(total_findings=len(fir_findings)),
                total_findings_processed=len(fir_findings),
                sanitization_summary={"findings_sanitized": len(fir_findings)},
                evidence_trust_score=metrics["trust_score"],
                evidence_quality_summary=metrics,
                readiness_blockers=metrics["readiness_blockers"],
                execution_status="FAILED",
                failure_type="MODEL_UNAVAILABLE",
                error_message=f"LLM invocation error: {str(exc)}"
            )
            self._persist_agent_output(output)
            return output.model_dump()

        # ── 4. Parse Structured JSON Response (Fail-Closed) ───────────────
        parsed_dict, raw_claims_list, parse_err = self._parse_json_response(llm_response)
        if parse_err or not parsed_dict:
            logger.error("Agent 1: Fail-closed due to malformed JSON response: %s", parse_err)
            output = Agent1Output(
                case_id=case_id,
                tenant_id=tenant_id,
                model_used=self.model_name,
                investigation_readiness=Agent1InvestigationReadiness(
                    status="READY_WITH_LIMITATIONS",
                    reason=f"LLM response parsing error: {parse_err}"
                ),
                evidence_summary=Agent1EvidenceSummary(total_findings=len(fir_findings)),
                total_findings_processed=len(fir_findings),
                sanitization_summary={"findings_sanitized": len(fir_findings)},
                evidence_trust_score=metrics["trust_score"],
                evidence_quality_summary=metrics,
                readiness_blockers=metrics["readiness_blockers"],
                execution_status="FAILED",
                failure_type="MALFORMED_OUTPUT",
                error_message=f"Malformed LLM JSON output: {parse_err}"
            )
            self._persist_agent_output(output)
            return output.model_dump()

        # ── 5. Evidence Reference Gate & Deterministic Validation ─────────
        valid_finding_ids, valid_lineage_ids = self.validator.extract_valid_id_universe(fir_findings)
        validated_dict, invalid_citations = self.validator.validate_triage_output(
            output_dict=parsed_dict,
            valid_finding_ids=valid_finding_ids,
            valid_lineage_ids=valid_lineage_ids
        )

        validated_claims = self.validator.validate_claims(
            claims=raw_claims_list,
            valid_finding_ids=valid_finding_ids,
            valid_lineage_ids=valid_lineage_ids
        )

        status = "SUCCESS"
        if invalid_citations:
            logger.warning("Agent 1: Evidence Reference Gate flagged invalid citations: %s", invalid_citations)
            status = "PARTIAL_SUCCESS"

        # Construct Agent1Output from validated dict & deterministic metrics
        try:
            output = Agent1Output(
                case_id=case_id,
                tenant_id=tenant_id,
                model_used=self.model_name,
                timestamp=datetime.now(timezone.utc),
                investigation_readiness=validated_dict.get(
                    "investigation_readiness",
                    Agent1InvestigationReadiness(
                        status=metrics["readiness_status"],
                        reason=metrics["readiness_reason"]
                    )
                ),
                evidence_summary=validated_dict.get(
                    "evidence_summary",
                    Agent1EvidenceSummary(total_findings=len(fir_findings))
                ),
                priority_evidence=validated_dict.get("priority_evidence", []),
                supporting_evidence=validated_dict.get("supporting_evidence", []),
                evidence_clusters=validated_dict.get("evidence_clusters", []),
                investigation_questions=validated_dict.get("investigation_questions", []),
                focus_areas=validated_dict.get("focus_areas", []),
                evidence_gaps=validated_dict.get("evidence_gaps", []),
                coverage=validated_dict.get("coverage", metrics["coverage"]),
                downstream_relevance=validated_dict.get("downstream_relevance", {}),
                limitations=validated_dict.get("limitations", []),
                
                # Backward compatibility fields
                claims=validated_claims,
                total_findings_processed=len(fir_findings),
                sanitization_summary={
                    "findings_sanitized": len(fir_findings),
                    "injections_flagged": injections_flagged_count,
                    "invalid_citations_blocked": invalid_citations
                },
                evidence_trust_score=metrics["trust_score"],
                evidence_quality_summary=metrics,
                readiness_blockers=metrics["readiness_blockers"],
                execution_status=status
            )
        except Exception as exc:
            logger.error("Agent 1: Output construction error: %s", exc)
            output = Agent1Output(
                case_id=case_id,
                tenant_id=tenant_id,
                model_used=self.model_name,
                total_findings_processed=len(fir_findings),
                evidence_trust_score=metrics["trust_score"],
                evidence_quality_summary=metrics,
                execution_status="FAILED",
                failure_type="SCHEMA_VALIDATION_ERROR",
                error_message=f"Output Pydantic construction failure: {str(exc)}"
            )

        # ── 6. Idempotent PostgreSQL Persistence ───────────────────────────
        self._persist_agent_output(output)

        return output.model_dump()

    def _parse_json_response(self, raw_text: str) -> Tuple[Optional[Dict[str, Any]], List[Agent1Claim], Optional[str]]:
        """Extracts JSON dict & Agent1Claim objects from LLM response string."""
        if not raw_text:
            return None, [], "Empty LLM output"

        cleaned = raw_text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(cleaned)
            if not isinstance(data, dict):
                return None, [], "Parsed JSON is not a dictionary"

            parsed_claims: List[Agent1Claim] = []
            claims_list = data.get("claims", [])
            if isinstance(claims_list, list):
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

                        conf = item.get("confidence_score", item.get("confidence", 0.8))
                        try:
                            conf = float(conf)
                        except (ValueError, TypeError):
                            conf = -1.0

                        missing_ev = item.get("missing_evidence_noted", [])
                        if isinstance(missing_ev, str):
                            missing_ev = [missing_ev.strip()] if missing_ev.strip() else []
                        elif not isinstance(missing_ev, list):
                            missing_ev = []

                        uncertainties = item.get("uncertainties_or_conflicts", [])
                        if isinstance(uncertainties, str):
                            uncertainties = [uncertainties.strip()] if uncertainties.strip() else []
                        elif not isinstance(uncertainties, list):
                            uncertainties = []

                        claim_obj = Agent1Claim(
                            claim_id=cid,
                            summary=summary,
                            findings_summary=findings_summary,
                            cited_evidence_ids=cited_ids,
                            assessed_importance=importance,
                            confidence_score=conf,
                            missing_evidence_noted=missing_ev,
                            uncertainties_or_conflicts=uncertainties,
                            reasoning_notes=item.get("reasoning_notes", "")
                        )
                        parsed_claims.append(claim_obj)

            return data, parsed_claims, None
        except Exception as err:
            logger.warning("Failed to parse LLM response as JSON: %s. Raw text: %s", err, raw_text[:200])
            return None, [], f"JSON parse error: {str(err)}"

    def _persist_agent_output(self, output: Agent1Output):
        """
        Persists Agent 1 output into PostgreSQL `agent_outputs` table using idempotent UPSERT.
        Does NOT create duplicate execution records for unchanged case/tenant/claim states.
        """
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
            _ensure_agent_outputs_table_initialized(conn)
            cur = conn.cursor()

            query = """
                INSERT INTO agent_outputs 
                    (case_id, tenant_id, agent_id, model_used, claim, evidence_ids, confidence, verified, execution_status, flags, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, case_id, agent_id, claim) DO UPDATE SET
                    tenant_id = EXCLUDED.tenant_id,
                    model_used = EXCLUDED.model_used,
                    evidence_ids = EXCLUDED.evidence_ids,
                    confidence = EXCLUDED.confidence,
                    verified = EXCLUDED.verified,
                    execution_status = EXCLUDED.execution_status,
                    flags = EXCLUDED.flags,
                    created_at = EXCLUDED.created_at;
            """

            readiness_str = output.investigation_readiness.status if hasattr(output.investigation_readiness, "status") else "READY"
            claim_summary = f"Agent 1 Triage Summary (Readiness: {readiness_str}, High Value: {output.evidence_summary.high_value_findings})"

            all_cited_ids = []
            for item in output.priority_evidence:
                if hasattr(item, "evidence_id"):
                    all_cited_ids.append(item.evidence_id)

            flags_dict = {
                "evidence_summary": output.evidence_summary.model_dump(mode="json") if hasattr(output.evidence_summary, "model_dump") else output.evidence_summary,
                "evidence_clusters_count": len(output.evidence_clusters),
                "investigation_questions_count": len(output.investigation_questions),
                "focus_areas_count": len(output.focus_areas),
                "evidence_gaps_count": len(output.evidence_gaps),
                "sanitization_summary": output.sanitization_summary,
                "error_message": output.error_message
            }

            cur.execute(
                query,
                (
                    output.case_id,
                    output.tenant_id,
                    output.agent_id,
                    output.model_used,
                    claim_summary,
                    all_cited_ids,
                    output.evidence_trust_score or 1.0,
                    output.execution_status == "SUCCESS",
                    output.execution_status,
                    json.dumps(flags_dict),
                    output.timestamp
                )
            )

            conn.commit()
            conn.close()
            logger.info("Agent 1 output persisted to PostgreSQL agent_outputs table for case %s", output.case_id)
        except Exception as exc:
            logger.warning("PostgreSQL agent_outputs persist error: %s", exc)
