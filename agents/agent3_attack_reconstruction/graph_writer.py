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
            # 1. Clear pre-existing AttackStep nodes for this case_id & tenant_id
            self._exec_cypher(
                "MATCH (s:AttackStep {case_id: $case_id, tenant_id: $tenant_id}) DETACH DELETE s",
                {"case_id": case_id, "tenant_id": tenant_id}
            )

            # 2. Write AttackStep nodes & SUPPORTED_BY evidence links
            steps = output.attack_path or []
            previous_step_id = None

            for step in sorted(steps, key=lambda x: x.step_number):
                step_id = f"STEP-{case_id}-{step.step_number:02d}"

                # Create AttackStep node
                self._exec_cypher(
                    """
                    MERGE (s:AttackStep {id: $step_id, case_id: $case_id, tenant_id: $tenant_id})
                    SET s.step_number = $step_number,
                        s.stage = $stage,
                        s.description = $description,
                        s.confidence = $confidence
                    """,
                    {
                        "step_id": step_id,
                        "case_id": case_id,
                        "tenant_id": tenant_id,
                        "step_number": step.step_number,
                        "stage": step.stage,
                        "description": step.description,
                        "confidence": step.confidence
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

                # Link SUPPORTED_BY relationships to Artifact nodes in Evidence Graph
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
