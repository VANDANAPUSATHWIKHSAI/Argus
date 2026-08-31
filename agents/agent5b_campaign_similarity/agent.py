# Agent 5b — Campaign / Behavior Similarity + Validated Case RAG
# [JOIN — runs only after Agent 3 AND Agent 4 complete]
# Joins outputs of Agent 3, Agent 4, Agent 5a.
# Compares current case against prior validated cases via RAG (Qdrant).
# Model: Qwen3-Embedding-4B + Qwen3-14B | RAG: YES (Qdrant)
from agents.base_agent import BaseAgent

class CampaignSimilarityAgent(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        vector_store = context.get("vector_store")
        if not vector_store:
            raise ValueError("vector_store must be provided in context.")
            
        # Search Qdrant for similar validated case profiles (wrapped in Sanitization Gateway)
        similar_cases = self.sanitized_context_fetch(
            vector_store.search,
            collection="validated_cases",
            query_vector=[0.1] * 384,  # example dummy query vector
            top_k=3,
            field_name="unstructured"
        )
        
        prompt = f"Identify campaign similarities based on these historic case materials:\n{similar_cases}"
        response = self.model.generate(prompt)
        
        return {
            "claim": response,
            "evidence_ids": []
        }

