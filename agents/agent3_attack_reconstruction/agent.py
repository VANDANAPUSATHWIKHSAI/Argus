"""
Agent 3 — Attack Reconstruction Agent
======================================
Second reasoning layer over sanitized forensic findings.
Model: Qwen3-8B (Required primary reasoning model)
RAG: No

Flow:
  FIR Findings + Agent 2 Signals 
               -> Deterministic Candidate Path Engine & Missing Event Detector
               -> Evidence Sanitization Gateway 
               -> Qwen3-8B Reasoning (with Mock/Dev Fallback)
               -> Deterministic Validation Gate 
               -> PostgreSQL Persistence
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set

from agents.base_agent import BaseAgent
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway, SanitizedAgentContext
from models.llm import LLMLoader
from config.settings import settings

from agents.agent3_attack_reconstruction.schemas import (
    Agent3Output, InfectionPath, AttackPathStep, AttackTimelineEvent, AttackChainStage,
    LateralMovement, MissingExpectedEvent
)
from agents.agent3_attack_reconstruction.path_builder import CandidatePathBuilder
from agents.agent3_attack_reconstruction.missing_event_detector import MissingEventDetector
from agents.agent3_attack_reconstruction.prompts import AGENT3_SYSTEM_PROMPT, build_agent3_user_prompt
from agents.agent3_attack_reconstruction.validator import Agent3Validator
from agents.agent3_attack_reconstruction.graph_writer import AttackPathGraphWriter

logger = logging.getLogger(__name__)


class AttackReconstructionAgent(BaseAgent):
    """
    Agent 3 — Attack Reconstruction Agent.
    Reconstructs attack timeline, kill-chain, infection source, lateral movement,
    and missing expected events using deterministic engines and LLM reasoning.
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
        self.validator = Agent3Validator()
        self.path_builder = CandidatePathBuilder()
        self.missing_detector = MissingEventDetector()
        self.model_name = "Qwen3-8B"

    def run(self, case_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes Agent 3 analysis over sanitized FIR findings for the given case_id.
        """
        context = context or {}
        tenant_id = context.get("tenant_id", self.tenant_id)
        neo4j_client = context.get("neo4j_client")
        if neo4j_client:
            self.path_builder.neo4j_client = neo4j_client
        
        # 1. Fetch FIR findings
        fir_findings = context.get("fir_findings")
        if not fir_findings:
            if hasattr(self.fir, "get_by_case"):
                fir_findings = self.sanitized_context_fetch(self.fir.get_by_case, tenant_id=tenant_id, case_id=case_id)
            elif hasattr(self.fir, "get_all"):
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
                infection_path=InfectionPath(entry_point="No evidence available", evidence_ids=[], confidence=0.0),
                attack_timeline=[],
                attack_chain=[],
                lateral_movement=[],
                missing_expected_events=[],
                reconstruction_summary="No FIR evidence findings found to perform attack reconstruction.",
                overall_confidence=0.0,
                execution_status="FAILED",
                error_message=f"No FIR findings found for case {case_id}"
            )
            from agents.agent3_attack_reconstruction.report import Agent3ReportGenerator
            output.investigator_report = Agent3ReportGenerator.generate(output)
            return output.model_dump()

        # 2. Sanitize context
        sanitized_contexts: List[SanitizedAgentContext] = []
        for finding in fir_findings:
            if isinstance(finding, SanitizedAgentContext):
                sanitized_contexts.append(finding)
            else:
                sanitized_ctx = self.gateway.sanitize_finding(finding)
                sanitized_contexts.append(sanitized_ctx)

        xml_blocks = "\n".join(ctx.xml_evidence_block for ctx in sanitized_contexts)

        # 3. Deterministic candidate path & missing event detection
        # Note: Cypher candidate path traversal utilizes: case_id: $case_id, tenant_id: $tenant_id
        agent2_correlation = context.get("agent2_correlation")
        candidate_paths_res = self.path_builder.build_candidate_paths(case_id, tenant_id, fir_findings, agent2_correlation)
        detected_missing_events = self.missing_detector.detect_missing_events(fir_findings)

        candidate_paths_xml = json.dumps(candidate_paths_res, default=str)
        missing_events_xml = json.dumps([m.model_dump(mode="json") for m in detected_missing_events], default=str)

        # 4. Construct prompt & invoke LLM
        user_prompt = build_agent3_user_prompt(
            case_id=case_id, 
            sanitized_xml_blocks=xml_blocks, 
            correlation_data=json.dumps(agent2_correlation, default=str) if agent2_correlation else "", 
            candidate_paths=candidate_paths_xml,
            missing_events_data=missing_events_xml
        )
        
        llm_response = ""
        llm_error = None
        try:
            if hasattr(self.model, "generate"):
                llm_response = self.model.generate(user_prompt, system_prompt=AGENT3_SYSTEM_PROMPT)
            elif callable(self.model):
                llm_response = self.model(user_prompt)
            else:
                llm_error = "Model instance lacks callable or generate method"
                logger.warning("Agent 3: LLM instance lacks callable/generate method. Using fallback synthesis.")
        except Exception as exc:
            llm_error = str(exc)
            logger.warning("Agent 3: LLM invocation encounter (%s). Utilizing deterministic synthesis fallback.", exc)
            llm_response = ""

        # 5. Parse output with robust fallback generator
        valid_finding_ids, valid_lineage_ids = self.validator.extract_valid_id_universe(
            fir_findings, case_id=case_id, tenant_id=tenant_id
        )
        valid_universe = valid_finding_ids.union(valid_lineage_ids)

        output = self._parse_json_to_output(
            llm_response=llm_response,
            case_id=case_id,
            tenant_id=tenant_id,
            fir_findings=fir_findings,
            candidate_paths_res=candidate_paths_res,
            detected_missing_events=detected_missing_events,
            valid_universe=valid_universe,
            llm_error=llm_error
        )

        # 6. Validate citations and calculate grounded confidence
        output = self.validator.validate_output(output, valid_finding_ids, valid_lineage_ids)

        output.total_findings_processed = len(fir_findings)
        output.sanitization_summary = {
            "findings_sanitized": len(sanitized_contexts),
            "injections_flagged": sum(1 for c in sanitized_contexts if c.injection_flagged)
        }

        # 7. Generate investigator report
        from agents.agent3_attack_reconstruction.report import Agent3ReportGenerator
        output.investigator_report = Agent3ReportGenerator.generate(output)

        # 8. Non-blocking PostgreSQL persistence
        self._persist_agent_output(output)

        # 9. Deterministic Neo4j Attack Path Graph Sync
        try:
            writer = AttackPathGraphWriter(neo4j_client=self.path_builder.neo4j_client)
            graph_synced = writer.sync_attack_path(output)
            if graph_synced is False and output.execution_status == "COMPLETED_WITH_FINDINGS":
                output.execution_status = "NEEDS_REVIEW"
                output.error_message = "Graph persistence was not completed."
        except Exception as exc:
            logger.warning("Agent 3 Neo4j graph sync note: %s", exc)
            if output.execution_status == "COMPLETED_WITH_FINDINGS":
                output.execution_status = "NEEDS_REVIEW"
                output.error_message = f"Graph persistence failed: {exc}"

        return output.model_dump()

    def _parse_json_to_output(
        self,
        llm_response: str,
        case_id: str,
        tenant_id: str,
        fir_findings: List[Any],
        candidate_paths_res: Dict[str, Any],
        detected_missing_events: List[MissingExpectedEvent],
        valid_universe: Set[str],
        llm_error: Optional[str] = None
    ) -> Agent3Output:
        parsed_dict = None
        json_parse_error = False
        if llm_response:
            cleaned = llm_response.strip()
            if "```json" in cleaned:
                cleaned = cleaned.split("```json")[1].split("```")[0].strip()
            elif "```" in cleaned:
                cleaned = cleaned.split("```")[1].split("```")[0].strip()

            try:
                parsed_dict = json.loads(cleaned)
            except Exception as err:
                json_parse_error = True
                logger.debug("Agent 3: Could not parse LLM output as JSON (%s). Using fallback synthesis.", err)
        elif llm_error:
            pass
        else:
            json_parse_error = True

        if parsed_dict and isinstance(parsed_dict, dict):
            # Check upstream status
            upstream_status = parsed_dict.get("execution_status")
            if upstream_status == "MODEL_UNAVAILABLE" or (llm_error and "MODEL_UNAVAILABLE" in str(llm_error)):
                target_status = "MODEL_UNAVAILABLE"
                err_msg = "MODEL_UNAVAILABLE: Model inference was offline or unavailable."
            elif upstream_status == "EXECUTION_FAILED":
                target_status = "EXECUTION_FAILED"
                err_msg = parsed_dict.get("error_message") or "Model execution failed upstream."
            else:
                target_status = None
                err_msg = None

            try:
                norm_data = self.validator.normalize_raw_dict(parsed_dict, valid_universe)
                
                # Merge rule-detected missing events if not present
                existing_missing_events = norm_data.get("missing_expected_events") or []
                existing_texts = {m.get("event") for m in existing_missing_events if isinstance(m, dict)}
                for det in detected_missing_events:
                    if det.event not in existing_texts:
                        existing_missing_events.append(det.model_dump(mode="json"))
                norm_data["missing_expected_events"] = existing_missing_events

                if not target_status:
                    has_steps = bool(norm_data.get("attack_path") or norm_data.get("attack_timeline"))
                    if has_steps:
                        target_status = "COMPLETED_WITH_FINDINGS"
                    else:
                        target_status = "COMPLETED_WITH_NO_FINDINGS"

                return Agent3Output(
                    agent_id="agent_3",
                    execution_status=target_status,
                    error_message=err_msg,
                    total_findings_processed=len(fir_findings),
                    case_id=case_id,
                    tenant_id=tenant_id,
                    model_used=self.model_name,
                    infection_path=InfectionPath(**norm_data["infection_path"]),
                    attack_path=[AttackPathStep(**x) for x in norm_data["attack_path"]],
                    attack_timeline=[AttackTimelineEvent(**x) for x in norm_data["attack_timeline"]],
                    attack_chain=[AttackChainStage(**x) for x in norm_data["attack_chain"]],
                    lateral_movement=[LateralMovement(**x) for x in norm_data["lateral_movement"]],
                    missing_expected_events=[MissingExpectedEvent(**x) for x in norm_data["missing_expected_events"]],
                    reconstruction_summary=norm_data["reconstruction_summary"],
                    overall_confidence=0.0 if target_status in ("MODEL_UNAVAILABLE", "EXECUTION_FAILED", "VALIDATION_FAILED") else norm_data["overall_confidence"]
                )
            except Exception as exc:
                logger.warning("Agent 3: Normalization/Validation error (%s).", exc)
                return Agent3Output(
                    agent_id="agent_3",
                    execution_status="VALIDATION_FAILED",
                    error_message=f"VALIDATION_FAILED: Schema or citation normalization error: {exc}",
                    total_findings_processed=len(fir_findings),
                    case_id=case_id,
                    tenant_id=tenant_id,
                    model_used=self.model_name,
                    infection_path=InfectionPath(entry_point="Validation failure", confidence=0.0),
                    attack_path=[],
                    attack_timeline=[],
                    attack_chain=[],
                    lateral_movement=[],
                    missing_expected_events=[],
                    reconstruction_summary=f"Agent 3 output validation failed: {exc}",
                    overall_confidence=0.0
                )

        # Fallback Deterministic Generator
        fallback_err = llm_error or ("JSON_PARSE_ERROR: Response unparseable as JSON" if json_parse_error else "EXECUTION_FAILED: No response received")
        return self._generate_deterministic_fallback(
            case_id=case_id,
            tenant_id=tenant_id,
            fir_findings=fir_findings,
            candidate_paths_res=candidate_paths_res,
            detected_missing_events=detected_missing_events,
            valid_universe=valid_universe,
            llm_error=fallback_err
        )

    def _generate_deterministic_fallback(
        self,
        case_id: str,
        tenant_id: str,
        fir_findings: List[Any],
        candidate_paths_res: Dict[str, Any],
        detected_missing_events: List[MissingExpectedEvent],
        valid_universe: Set[str],
        llm_error: Optional[str] = None
    ) -> Agent3Output:
        valid_ids = list(valid_universe)[:5] if valid_universe else [str(self._get_val(f, "finding_id")) for f in fir_findings if self._get_val(f, "finding_id")][:5]
        
        # Determine infection path only if verified malicious indicators exist
        has_malicious = any(self._get_val(f, "severity") in ("high", "critical") for f in fir_findings)
        earliest_fact = "No confirmed malicious intrusion vector in examined findings"
        earliest_id = valid_ids[0] if valid_ids else "unknown"
        if fir_findings and has_malicious:
            f0 = fir_findings[0]
            earliest_fact = f"Potential entry indicator: {self._get_val(f0, 'fact') or self._get_val(f0, 'event_summary') or 'Observable'}"
            earliest_id = str(self._get_val(f0, "finding_id") or earliest_id)

        inf_path = InfectionPath(
            entry_point=earliest_fact[:120],
            evidence_ids=[earliest_id] if (earliest_id != "unknown" and has_malicious) else [],
            confidence=0.0 if (llm_error or not has_malicious) else 0.40,
            citation_verified=bool(earliest_id in valid_universe and has_malicious)
        )

        # Construct attack timeline from findings
        timeline_events = []
        for idx, f in enumerate(fir_findings[:10]):
            fid = str(self._get_val(f, "finding_id") or (valid_ids[0] if valid_ids else f"f-{idx}"))
            fact = str(self._get_val(f, "fact") or self._get_val(f, "event_summary") or f"Finding {idx}")
            ts = str(self._get_val(f, "timestamp") or "2026-10-03T10:00:00Z")
            stage = self.path_builder._classify_stage(fact)
            if not has_malicious and stage in ("Initial Access", "Execution", "Persistence", "Command and Control"):
                stage = "User Activity Observation"
            
            timeline_events.append(
                AttackTimelineEvent(
                    timestamp=ts,
                    event=fact[:150],
                    stage=stage,
                    evidence_ids=[fid] if fid in valid_universe else [],
                    confidence=0.0 if (llm_error or not has_malicious) else 0.40,
                    citation_verified=bool(fid in valid_universe and has_malicious)
                )
            )

        # Group attack chain by stage
        chain_stages = []
        stage_groups = {}
        for te in timeline_events:
            stage_groups.setdefault(te.stage, []).append((te.event, te.evidence_ids[0] if te.evidence_ids else "unknown"))

        for stage, items in stage_groups.items():
            evts = [it[0] for it in items]
            eids = list({it[1] for it in items if it[1] != "unknown" and it[1] in valid_universe})
            chain_stages.append(
                AttackChainStage(
                    stage=stage,
                    events=evts,
                    evidence_ids=eids,
                    confidence=0.0 if (llm_error or not has_malicious) else 0.40,
                    citation_verified=bool(all(eid in valid_universe for eid in eids) and bool(eids))
                )
            )

        # Lateral movement check
        lateral_movs = []
        for f in fir_findings:
            fact = str(self._get_val(f, "fact") or "").lower()
            fid = str(self._get_val(f, "finding_id") or "")
            if fid and ("smb" in fact or "rdp" in fact or "4624" in fact or "remote session" in fact):
                src = str(self._get_val(f, "source_host") or self._get_val(f, "host") or "Source Host")
                dst = str(self._get_val(f, "dest_host") or self._get_val(f, "destination_host") or "Target Host")
                lateral_movs.append(
                    LateralMovement(
                        source_host=src,
                        destination_host=dst,
                        method="Network Session",
                        evidence_ids=[fid] if fid in valid_universe else [],
                        confidence=0.0 if (llm_error or not has_malicious) else 0.40,
                        citation_verified=bool(fid in valid_universe and has_malicious)
                    )
                )

        if llm_error and ("MODEL_UNAVAILABLE" in str(llm_error) or "unavailable" in str(llm_error).lower()):
            exec_status = "MODEL_UNAVAILABLE"
            err_msg = f"MODEL_UNAVAILABLE: {llm_error}"
            conf = 0.0
            summary = (
                f"Attack reconstruction model inference unavailable: {llm_error}. "
                f"Constructed deterministic fallback baseline from {len(fir_findings)} evidence findings."
            )
        elif llm_error:
            exec_status = "EXECUTION_FAILED"
            err_msg = f"EXECUTION_FAILED: {llm_error}"
            conf = 0.0
            summary = (
                f"Attack reconstruction model execution failed: {llm_error}. "
                f"Constructed deterministic fallback baseline from {len(fir_findings)} evidence findings."
            )
        else:
            exec_status = "NEEDS_REVIEW"
            err_msg = "SYNTHESIS_DEGRADED: Model response unparseable as JSON; synthesized deterministic timeline"
            conf = 0.0 if not has_malicious else round(min(0.50, max(0.10, len(fir_findings) / 20.0)), 2)
            summary = (
                f"Attack reconstruction for case {case_id} synthesized {len(fir_findings)} evidence findings. "
                f"Candidate attack paths linked {candidate_paths_res.get('path_count', 0)} correlation nodes. "
                f"Identified infection entry point and {len(timeline_events)} chronological timeline events."
            )

        attack_path_steps = []
        for idx, te in enumerate(timeline_events, 1):
            attack_path_steps.append(
                AttackPathStep(
                    step_number=idx,
                    stage=te.stage,
                    description=te.event,
                    evidence_ids=te.evidence_ids,
                    confidence=te.confidence,
                    citation_verified=te.citation_verified
                )
            )

        return Agent3Output(
            agent_id="agent_3",
            execution_status=exec_status,
            error_message=err_msg,
            total_findings_processed=len(fir_findings),
            case_id=case_id,
            tenant_id=tenant_id,
            model_used=self.model_name,
            infection_path=inf_path,
            attack_path=attack_path_steps,
            attack_timeline=timeline_events,
            attack_chain=chain_stages,
            lateral_movement=lateral_movs,
            missing_expected_events=detected_missing_events,
            reconstruction_summary=summary,
            overall_confidence=conf
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
                "error_message": output.error_message
            }

            # Defect 10: Persist actual verification state, not unverified=True
            is_verified = (
                output.execution_status == "SUCCESS"
                and getattr(output.infection_path, "citation_verified", True) is not False
                and all(getattr(step, "citation_verified", True) is not False for step in getattr(output, "attack_path", []))
            )

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
                    is_verified,
                    output.execution_status,
                    json.dumps(flags_dict),
                    output.timestamp
                )
            )
            
            conn.commit()
            conn.close()
            logger.info("Agent 3 output persisted to PostgreSQL agent_outputs table for case %s", output.case_id)
        except Exception as exc:
            logger.debug("PostgreSQL agent_outputs non-blocking persist note: %s", exc)

    def _get_val(self, obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)
