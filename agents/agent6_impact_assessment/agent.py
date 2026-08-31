# Agent 6 — Impact Assessment
# Affected assets, user/business impact, severity scoring, recovery recs.
# CVSS-style formula scoring (reproducible/auditable, not generated).
# LLM narrates the computed result.
# Model: Qwen3-14B | Tools: CVSS + rule engine, PostgreSQL | RAG: No
from agents.base_agent import BaseAgent

class ImpactAssessmentAgent(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        # Retrieve raw database assets context from postgres
        raw_assets = context.get("affected_assets", [])
        
        # Sanitize potentially attacker-controlled hostnames/usernames (wrapped in Sanitization Gateway)
        sanitized_assets = self.sanitized_context_fetch(
            lambda: raw_assets,
            field_name="unstructured"
        )
        
        prompt = f"Narrate the business impact for the following compromised assets:\n{sanitized_assets}"
        response = self.model.generate(prompt)
        
        return {
            "claim": response,
            "evidence_ids": []
        }

