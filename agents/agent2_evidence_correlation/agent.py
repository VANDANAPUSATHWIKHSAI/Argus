# Agent 2 — Evidence Correlation
# Graph algorithms first (Neo4j GDS — community detection, temporal traversal).
# LLM only narrates the result — correlation is a graph problem, not language.
# Model: Qwen3-14B | Tools: Neo4j + GDS | RAG: No
from agents.base_agent import BaseAgent

class EvidenceCorrelationAgent(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        neo4j_client = context.get("neo4j_client")
        if not neo4j_client:
            raise ValueError("Neo4jClient must be provided in context.")
            
        # Retrieve correlation community detections from Neo4j (wrapped in Sanitization Gateway)
        correlation_results = self.sanitized_context_fetch(
            neo4j_client.query,
            "MATCH (a:Artifact)-[r:CORRELATED]-(b:Artifact) "
            "WHERE a.case_id = $case_id RETURN a.id, b.id, type(r)",
            {"case_id": case_id},
            field_name="unstructured"
        )
        
        prompt = f"Narrate the following artifact correlations from Neo4j graph:\n{correlation_results}"
        response = self.model.generate(prompt)
        
        return {
            "claim": response,
            "evidence_ids": []  # Filled in production by traversing the correlation path
        }

