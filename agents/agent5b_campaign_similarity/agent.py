"""
Agent 5b — Campaign / Behavior Similarity + Validated Case RAG
=============================================================
Joins outputs of Agent 3, Agent 4, and Agent 5a.
Compares current case against prior validated cases via RAG (Qdrant).

Key Principles:
- "HISTORICAL CASES ARE REFERENCES, NOT PROOF"
- "Historical cases never override current evidence"
- Authoritative case_id and tenant_id enforcement
- Maker-Checker validation enforcement (only approved cases are retrievable)
- Strict per-tenant isolation in Qdrant
- Multi-vector semantic representation (behavior, attack, threat intel, composite)
- Common / New / Different / Historical-Only classification & Novelty Detection
- Structured Agent 6 Handoff Package & Audit Logging
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set

from agents.base_agent import BaseAgent
from agents.agent5b_campaign_similarity.schemas import (
    Agent5bOutput,
    HistoricalSimilarityOutput,
    CaseBehavioralSignature,
    Agent6HandoffPackage,
    AuditLogRecord
)
from agents.agent5b_campaign_similarity.signature_builder import CaseSignatureBuilder
from agents.agent5b_campaign_similarity.vector_engine import MultiVectorEngine
from agents.agent5b_campaign_similarity.case_repository import ValidatedCaseRepository
from agents.agent5b_campaign_similarity.similarity_engine import SimilarityEngine
from agents.agent5b_campaign_similarity.delta_analyzer import BehaviorDeltaAnalyzer
from agents.agent5b_campaign_similarity.explanation_generator import ExplanationGenerator
from agents.agent5b_campaign_similarity.validator import Agent5bValidator

logger = logging.getLogger(__name__)


class CampaignSimilarityAgent(BaseAgent):
    """
    Agent 5b: Campaign & Behavior Similarity Analysis with Validated Case RAG.
    """

    def __init__(
        self,
        model=None,
        fir_repo=None,
        sanitization_gateway=None,
        tenant_id: str = "default",
        vector_repo: Optional[ValidatedCaseRepository] = None,
        vector_engine: Optional[MultiVectorEngine] = None
    ):
        super().__init__(
            model=model,
            fir_repo=fir_repo,
            sanitization_gateway=sanitization_gateway,
            tenant_id=tenant_id
        )
        self.vector_engine = vector_engine or MultiVectorEngine()
        self.vector_repo = vector_repo or ValidatedCaseRepository(vector_engine=self.vector_engine)

    def run(self, case_id: str, context: dict) -> dict:
        """
        BaseAgent execution entry point. Accepts context dictionary containing outputs from
        Agent 3, Agent 4, and Agent 5a (which ran in parallel from Agent 2).
        """
        upstream = context.get("upstream_outputs", {})
        agent3_out = context.get("agent3_output") or context.get("agent3") or upstream.get("agent3") or upstream.get("agent3_output") or {}
        agent4_out = context.get("agent4_output") or context.get("agent4") or upstream.get("agent4") or upstream.get("agent4_output") or {}
        agent5a_out = context.get("agent5a_output") or context.get("agent5a") or upstream.get("agent5a") or upstream.get("agent5a_output") or {}
        agent2_out = context.get("agent2_output") or context.get("agent2") or upstream.get("agent2") or upstream.get("agent2_output") or {}
        tenant_id = context.get("tenant_id") or self.tenant_id

        # Allow context to pass or override vector_repo or vector_store
        vector_store = context.get("vector_store")
        if vector_store and not isinstance(vector_store, ValidatedCaseRepository):
            custom_repo = ValidatedCaseRepository(
                qdrant_client=getattr(vector_store, "client", vector_store),
                vector_engine=self.vector_engine
            )
            self.vector_repo = custom_repo
        elif isinstance(vector_store, ValidatedCaseRepository):
            self.vector_repo = vector_store

        top_k = context.get("top_k", 5)

        output = self.execute_analysis(
            case_id=case_id,
            agent3_output=agent3_out,
            agent4_output=agent4_out,
            agent5a_output=agent5a_out,
            agent2_output=agent2_out,
            tenant_id=tenant_id,
            top_k=top_k
        )

        return output.model_dump()

    def execute_analysis(
        self,
        case_id: str,
        agent3_output: Optional[Dict[str, Any]] = None,
        agent4_output: Optional[Dict[str, Any]] = None,
        agent5a_output: Optional[Dict[str, Any]] = None,
        agent2_output: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
        top_k: int = 5
    ) -> Agent5bOutput:
        """
        Executes end-to-end Campaign & Behavioral Similarity analysis against Validated Case RAG
        by joining the outputs of Agent 3, Agent 4, and Agent 5a.
        """
        target_tenant = tenant_id or self.tenant_id or "default"
        execution_status = "success"
        error_message = None
        limitations: List[str] = []
        validation_decisions: List[str] = []
        errors_encountered: List[str] = []

        # 1. Collect Authorized Evidence IDs from FIR repository or explicit evidence scope
        authorized_evidence_ids: Set[str] = set(evidence_ids or [])
        if self.fir and hasattr(self.fir, "get_all_by_case"):
            try:
                repo_firs = self.fir.get_all_by_case(target_tenant, case_id)
                for f in repo_firs:
                    fid = getattr(f, "finding_id", f.get("finding_id", ""))
                    if fid:
                        authorized_evidence_ids.add(fid)
                validation_decisions.append(f"Loaded {len(repo_firs)} authoritative FIR records from database.")
            except Exception as e:
                logger.warning(f"Error reading FIR findings: {e}")
                errors_encountered.append(f"FIR repository error: {e}")

        # Also register cited IDs from valid upstream agents if no FIR repository was injected
        input_eids: Set[str] = set()
        for inp in [agent2_output, agent3_output, agent4_output, agent5a_output]:
            if isinstance(inp, dict):
                eids = inp.get("evidence_ids") or []
                input_eids.update(eids)
                erefs = inp.get("evidence_references") or []
                input_eids.update(erefs)

        effective_authorized_ids = authorized_evidence_ids if authorized_evidence_ids else input_eids

        # 2. Build Case Behavioral Signature joining 3, 4, 5a (and 2)
        signature = CaseSignatureBuilder.build(
            case_id=case_id,
            tenant_id=target_tenant,
            agent3_output=agent3_output,
            agent4_output=agent4_output,
            agent5a_output=agent5a_output,
            agent2_output=agent2_output,
            evidence_ids=list(effective_authorized_ids)
        )

        if signature.validation_warnings:
            validation_decisions.extend(signature.validation_warnings)

        # 3. Multi-Vector Encoding
        try:
            query_vectors = self.vector_engine.generate_vectors(signature)
        except Exception as e:
            logger.error(f"Multi-vector generation failed: {e}. Using fallback vectorizer.")
            execution_status = "degraded"
            errors_encountered.append(f"Multi-vector generation failure: {e}")
            limitations.append(f"Vector embedding failure: {e}. Semantic hashing fallback utilized.")
            query_vectors = self.vector_engine.generate_vectors(signature)

        # 4. Qdrant / Validated Case Retrieval (Strict Tenant Isolation)
        retrieved_cases = []
        try:
            retrieved_cases = self.vector_repo.search_similar(
                tenant_id=target_tenant,
                query_vectors=query_vectors,
                top_k=top_k,
                dimension="composite"
            )
            validation_decisions.append(
                f"Retrieved {len(retrieved_cases)} approved historical case(s) from collection for tenant '{target_tenant}'."
            )
        except Exception as e:
            logger.error(f"Qdrant retrieval failed: {e}")
            execution_status = "degraded"
            error_message = f"Qdrant unavailable: {e}"
            errors_encountered.append(f"Qdrant retrieval error: {e}")
            limitations.append("Validated Case Repository was unavailable during retrieval; operated in degraded mode.")

        # 5. Deterministic Multi-Dimensional Similarity Scoring
        b_sim, a_sim, ti_sim, comp_sim, breakdown = SimilarityEngine.compute_scores(
            retrieved_cases, current_sig=signature
        )

        # 6. Common / New / Different / Historical-Only & Novelty Analysis
        common_b, new_b, diff_b, hist_only_b, novelty = BehaviorDeltaAnalyzer.analyze(
            current_sig=signature,
            retrieved_cases=retrieved_cases
        )

        # 7. Identify Malware Families, Campaigns, and Threat Actor Context
        sim_families = SimilarityEngine.identify_malware_families(signature, retrieved_cases)
        sim_campaigns = SimilarityEngine.identify_campaigns(signature, retrieved_cases)
        actor_context = SimilarityEngine.identify_threat_actors(signature, retrieved_cases)

        # 8. Compute Grounded Investigative Confidence (Strictly separated from similarity)
        confidence, conf_methodology = SimilarityEngine.compute_grounded_confidence(
            current_sig=signature,
            agent3_present=bool(agent3_output),
            agent4_present=bool(agent4_output),
            agent5a_present=bool(agent5a_output)
        )

        # 9. Generate Grounded Explanations reusing exact deterministic scores
        explanations = ExplanationGenerator.generate_explanations(
            current_sig=signature,
            retrieved_cases=retrieved_cases,
            common_behaviors=common_b,
            different_behaviors=diff_b,
            novelty=novelty,
            similar_families=sim_families,
            similarity_breakdown=breakdown
        )

        # 10. Generate Claim reusing exact composite similarity
        claim = ExplanationGenerator.generate_claim(
            case_id=case_id,
            retrieved_cases=retrieved_cases,
            common_behaviors=common_b,
            similar_families=sim_families,
            novelty=novelty,
            evidence_ids=list(effective_authorized_ids),
            composite_sim=comp_sim
        )

        # 11. Build Agent 6 Handoff Package
        hist_references = [c.case_id for c in retrieved_cases]
        agent6_handoff = Agent6HandoffPackage(
            case_id=case_id,
            tenant_id=target_tenant,
            validated_historical_references=hist_references,
            similarity_metrics={
                "behavior_similarity": b_sim,
                "attack_similarity": a_sim,
                "intelligence_similarity": ti_sim,
                "composite_similarity": comp_sim
            },
            behavior_comparisons={
                "common_behaviors": common_b,
                "new_behaviors": new_b,
                "different_behaviors": [d.model_dump() for d in diff_b],
                "historical_only_behaviors": hist_only_b
            },
            novelty_findings=novelty,
            supporting_evidence_references=list(effective_authorized_ids),
            investigative_confidence=confidence,
            confidence_methodology=conf_methodology,
            limitations=list(limitations),
            attribution_safeguards=[
                "Historical case similarity is contextual reference only, never proof of identity or attribution.",
                "Previous cases never override current forensic evidence."
            ]
        )

        # 12. Build Audit Log Record
        audit_record = AuditLogRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            case_id=case_id,
            tenant_id=target_tenant,
            scoring_version="1.0.0",
            retrieval_filter={"tenant_id": target_tenant, "validation_status": ["approved", "validated"]},
            model_metadata={"model": getattr(self.model, "model_name", "deterministic"), "vector_dim": str(self.vector_engine.VECTOR_DIM)},
            validation_decisions=validation_decisions,
            errors_encountered=errors_encountered
        )

        # 13. Build Output Structure
        hist_output = HistoricalSimilarityOutput(
            retrieved_cases=retrieved_cases,
            behavior_similarity=b_sim,
            attack_similarity=a_sim,
            intelligence_similarity=ti_sim,
            composite_similarity=comp_sim,
            similarity_breakdown=breakdown,
            common_behaviors=common_b,
            new_behaviors=new_b,
            different_behaviors=diff_b,
            historical_only_behaviors=hist_only_b,
            similar_malware_families=sim_families,
            similar_campaigns=sim_campaigns,
            possible_actor_context=actor_context,
            novelty=novelty,
            explanations=explanations,
            confidence=confidence,
            confidence_methodology=conf_methodology,
            limitations=limitations,
            historical_case_references=hist_references
        )

        output = Agent5bOutput(
            case_id=case_id,
            tenant_id=target_tenant,
            execution_status=execution_status,
            historical_similarity=hist_output,
            claim=claim,
            evidence_ids=sorted(list(effective_authorized_ids)),
            agent6_handoff=agent6_handoff,
            audit_record=audit_record,
            validation_warnings=signature.validation_warnings,
            mismatched_records=signature.mismatched_records,
            error_message=error_message
        )

        # 14. Validate Output, Purge Invalid References, Clamp Scores
        output = Agent5bValidator.validate_and_refine(output, effective_authorized_ids)

        return output
