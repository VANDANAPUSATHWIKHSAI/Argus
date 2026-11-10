"""
Agent 3 — Deterministic Attack Path Graph Writer for Neo4j
============================================================
Pushes validated AttackPathStep nodes, NEXT sequence edges, SUPPORTED_BY
evidence relationships, and LATERAL_MOVEMENT host edges into Neo4j.
"""

import logging
from typing import Any, Optional, Dict
from agents.agent3_attack_reconstruction.schemas import Agent3Output

logger = logging.getLogger(__name__)


class AttackPathGraphWriter:
    """
    Deterministic writer that converts validated Agent3Output into an 
    Attack Path Graph in Neo4j, anchored to pre-existing Evidence Artifact nodes.
    """

    def __init__(self, neo4j_client: Optional[Any] = None):
        self.neo4j_client = neo4j_client

    def _exec_cypher(self, query: str, params: Dict[str, Any]):
        if not self.neo4j_client:
            return
        if hasattr(self.neo4j_client, "query"):
            self.neo4j_client.query(query, params)
        elif hasattr(self.neo4j_client, "session"):
            with self.neo4j_client.session() as session:
                session.run(query, params)

    def sync_attack_path(self, output: Agent3Output) -> bool:
        """
        Synchronizes validated Agent3Output attack sequence and lateral movement hops to Neo4j.
        """
        if not self.neo4j_client:
            logger.debug("AttackPathGraphWriter: Neo4j client unavailable, skipping Neo4j graph sync.")
            return False

        case_id = output.case_id
        tenant_id = output.tenant_id

        try:
            # Preserve existing graph state when execution failed or model was unavailable
            if output.execution_status in ("MODEL_UNAVAILABLE", "EXECUTION_FAILED", "VALIDATION_FAILED"):
                logger.info(
                    "Agent 3: Execution status is '%s'; skipping attack path graph sync for case %s to preserve historical state.",
                    output.execution_status, case_id
                )
                return True

            steps = output.attack_path or []
            if not steps:
                logger.info("Agent 3: No attack path steps to synchronize for case %s. Preserving graph state.", case_id)
                return True

            previous_step_id = None

            for step in sorted(steps, key=lambda x: x.step_number):
                step_id = f"STEP-{case_id}-{step.step_number:02d}"

                # Determine explicit provenance based on citation verification
                prov_type = getattr(step, "provenance_type", None)
                has_validated_citations = bool(step.evidence_ids and getattr(step, "citation_verified", False))

                if not prov_type:
                    prov_type = "EVIDENCE_CORRELATED" if has_validated_citations else "HYPOTHESIS"

                # Mandatory constraint: Cannot write OBSERVED or EVIDENCE_CORRELATED without validated citations
                if prov_type in ("OBSERVED", "EVIDENCE_CORRELATED") and not has_validated_citations:
                    logger.warning(
                        "Forensic constraint enforcement: Attack step %s claims %s "
                        "without validated evidence references. Demoting to HYPOTHESIS.",
                        step_id, prov_type
                    )
                    prov_type = "HYPOTHESIS"

                status_val = "CONFIRMED" if prov_type in ("OBSERVED", "EVIDENCE_CORRELATED") else "UNCONFIRMED_HYPOTHESIS"
                reasoning_text = getattr(step, "reasoning_basis", None) or (
                    step.description if prov_type in ("OBSERVED", "EVIDENCE_CORRELATED")
                    else f"Analytical hypothesis (unverified citations): {step.description}"
                )
                step_conf = step.confidence if prov_type in ("OBSERVED", "EVIDENCE_CORRELATED") else min(step.confidence or 0.35, 0.35)

                # Create or update AttackStep node preserving historical identities
                self._exec_cypher(
                    """
                    MERGE (s:AttackStep {id: $step_id, case_id: $case_id, tenant_id: $tenant_id})
                    SET s.step_number = $step_number,
                        s.stage = $stage,
                        s.description = $description,
                        s.confidence = $confidence,
                        s.provenance_type = $provenance_type,
                        s.status = $status,
                        s.reasoning_basis = $reasoning_basis
                    """,
                    {
                        "step_id": step_id,
                        "case_id": case_id,
                        "tenant_id": tenant_id,
                        "step_number": step.step_number,
                        "stage": step.stage,
                        "description": step.description,
                        "confidence": step_conf,
                        "provenance_type": prov_type,
                        "status": status_val,
                        "reasoning_basis": reasoning_text
                    }
                )

                # Connect sequential NEXT edge
                if previous_step_id:
                    self._exec_cypher(
                        """
                        MATCH (s1:AttackStep {id: $prev_id, case_id: $case_id, tenant_id: $tenant_id}),
                              (s2:AttackStep {id: $curr_id, case_id: $case_id, tenant_id: $tenant_id})
                        MERGE (s1)-[r:NEXT {case_id: $case_id, tenant_id: $tenant_id}]->(s2)
                        """,
                        {
                            "prev_id": previous_step_id,
                            "curr_id": step_id,
                            "case_id": case_id,
                            "tenant_id": tenant_id
                        }
                    )
                previous_step_id = step_id

                # Link SUPPORTED_BY relationships to Artifact nodes ONLY for evidence-correlated steps
                if prov_type in ("OBSERVED", "EVIDENCE_CORRELATED") and has_validated_citations:
                    for eid in step.evidence_ids:
                        self._exec_cypher(
                            """
                            MATCH (s:AttackStep {id: $step_id, case_id: $case_id, tenant_id: $tenant_id})
                            MERGE (a:Artifact {id: $eid, case_id: $case_id, tenant_id: $tenant_id})
                            MERGE (s)-[r:SUPPORTED_BY {case_id: $case_id, tenant_id: $tenant_id}]->(a)
                            """,
                            {
                                "step_id": step_id,
                                "eid": eid,
                                "case_id": case_id,
                                "tenant_id": tenant_id
                            }
                        )

            # 3. Write Lateral Movement Host nodes & LATERAL_MOVEMENT edges
            for lm in output.lateral_movement or []:
                self._exec_cypher(
                    """
                    MERGE (h1:Host {name: $src_host, case_id: $case_id, tenant_id: $tenant_id})
                    MERGE (h2:Host {name: $dst_host, case_id: $case_id, tenant_id: $tenant_id})
                    MERGE (h1)-[r:LATERAL_MOVEMENT {method: $method, case_id: $case_id, tenant_id: $tenant_id}]->(h2)
                    SET r.confidence = $confidence
                    """,
                    {
                        "src_host": lm.source_host,
                        "dst_host": lm.destination_host,
                        "method": lm.method,
                        "confidence": lm.confidence,
                        "case_id": case_id,
                        "tenant_id": tenant_id
                    }
                )

            logger.info("AttackPathGraphWriter: Successfully synchronized Attack Path Graph for case %s to Neo4j.", case_id)
            return True
        except Exception as exc:
            logger.warning("AttackPathGraphWriter: Neo4j attack path graph sync failed: %s", exc)
            return False
