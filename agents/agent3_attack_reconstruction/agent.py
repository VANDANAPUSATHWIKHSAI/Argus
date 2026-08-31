# Agent 3 — Attack Reconstruction  [runs PARALLEL with Agent 4, Agent 5a]
# Graph traversal over MITRE ATT&CK kill-chain graph (deterministic).
# LLM narrates the path — doesn't freely 'reason' a sequence.
# Model: Qwen3-14B | Tools: Neo4j GDS, MITRE ATT&CK | RAG: No
from agents.base_agent import BaseAgent

class AttackReconstructionAgent(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        neo4j_client = context.get("neo4j_client")
        mitre_client = context.get("mitre_client")
        if not neo4j_client or not mitre_client:
            raise ValueError("Both Neo4jClient and MitreAttackClient must be provided in context.")

        # Traverse kill chain in Neo4j (wrapped in Sanitization Gateway)
        kill_chain = self.sanitized_context_fetch(
            neo4j_client.query,
            "MATCH p=(:Step)-[:NEXT*]->(:Step) RETURN p",
            field_name="unstructured"
        )
        
        # Look up mapped techniques via MITRE client (wrapped in Sanitization Gateway)
        mitre_details = self.sanitized_context_fetch(
            mitre_client.get_technique,
            "T1059",
            field_name="description"
        )
        
        prompt = f"Narrate the reconstructed attack kill-chain timeline:\n{kill_chain}\nMITRE Details:\n{mitre_details}"
        response = self.model.generate(prompt)
        
        return {
            "claim": response,
            "evidence_ids": []
        }

