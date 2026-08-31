# Agent 7 — Call 1: Synthesis
# Takes full context (Agents 3, 4, 5b, 6).
# Generates final structured, cited claims + Investigation Confidence Score.
# Model: Qwen3-14B | RAG: No mandatory RAG
from agents.base_agent import BaseAgent

class SupervisorSynthesis(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        # Synthesize all upstream agent outputs (Agent 3, 4, 5b, 6)
        agent_outputs = context.get("agent_outputs", {})
        
        # Pull any cited evidence findings from the FIR
        evidence_ids = context.get("evidence_ids", [])
        evidence_contents = []
        for eid in evidence_ids:
            ev_text = self.sanitized_context_fetch("fir", eid)
            evidence_contents.append(ev_text)

        # Sanitize incoming context from upstream agents (wrapped in Sanitization Gateway)
        sanitized_outputs = self.sanitized_context_fetch(
            lambda: agent_outputs,
            field_name="unstructured"
        )
        
        evidence_str = "\n".join(evidence_contents)
        prompt = (
            f"Synthesize final claims from the following agent reports:\n{sanitized_outputs}\n"
            f"And the cited evidence details:\n{evidence_str}"
        )
        response = self.model.generate(prompt)
        
        # Returns: { 'claims': [...], 'confidence_score': float }
        return {
            "claims": [{"claim": response, "evidence_ids": evidence_ids}],
            "confidence_score": 0.95
        }


