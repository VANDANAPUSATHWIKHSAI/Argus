# Agent 1 — Evidence Intelligence
# First structured read of the FIR (via Sanitization Gateway).
# Produces initial interpretation of what the evidence shows.
# Model: Qwen3-14B | RAG: No
from agents.base_agent import BaseAgent

class EvidenceIntelligenceAgent(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        # Retrieve evidence findings from FIR, ensuring all text fields are sanitized
        findings = self.sanitized_context_fetch(self.fir.get_by_case, case_id, field_name="unstructured")
        
        prompt = f"Analyze the following forensic evidence:\n{findings}"
        response = self.model.generate(prompt)
        
        # Parse evidence IDs if findings are returned as dicts
        evidence_ids = []
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict) and "evidence_id" in f:
                    evidence_ids.append(f["evidence_id"])
                elif hasattr(f, "evidence_id"):
                    evidence_ids.append(f.evidence_id)
                    
        return {
            "claim": response,
            "evidence_ids": evidence_ids
        }

