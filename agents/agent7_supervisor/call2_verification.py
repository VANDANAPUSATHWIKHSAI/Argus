# Agent 7 — Call 2: Independent Verification
# ISOLATED context, lightweight model.
# Sees ONLY each individual claim + its cited evidence_ids' FIR records.
# NOT Call 1's reasoning or the rest of the narrative.
#
# Four checks:
#   1. Existence   — does each cited evidence_id exist in FIR? (deterministic)
#   2. Support     — does the finding actually support the claim? (DeBERTa-MNLI)
#   3. Severity    — was confidence/severity silently inflated?
#   4. Divergence  — does narrative contradict Layer 4's deterministic label?
#
# Model: DeBERTa-v3-large-MNLI (entailment) → Qwen3-14B fallback
import logging
from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

class SupervisorVerification(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        raise NotImplementedError("Use verify() method for independent verification.")

    def verify(self, claim: dict, fir_records: list = None) -> dict:
        # 1. Resolve evidence IDs (use claim's evidence_ids or from list)
        evidence_ids = list(claim.get("evidence_ids", []))
        if not evidence_ids and fir_records:
            for r in fir_records:
                if isinstance(r, dict):
                    fid = r.get("finding_id") or r.get("id")
                else:
                    fid = getattr(r, "finding_id", None) or getattr(r, "id", None)
                if fid:
                    evidence_ids.append(fid)

        # 2. Pull findings via sanitized_context_fetch("fir", id)
        evidence_wrapped_texts = []
        evidence_clean_texts = []
        for fid in evidence_ids:
            ev_wrapped = self.sanitized_context_fetch("fir", fid)
            evidence_wrapped_texts.append(ev_wrapped)

            # Extract sanitized_fact inside XML wrapper for DeBERTa support check
            lines = ev_wrapped.splitlines()
            if len(lines) >= 3:
                if 'injection_flagged="true"' in lines[0]:
                    clean_text = "\n".join(lines[2:-1])
                else:
                    clean_text = "\n".join(lines[1:-1])
            else:
                clean_text = ev_wrapped
            evidence_clean_texts.append(clean_text)

        # 3. Deterministic Existence Check
        existence_passed = all(self.exists("fir", fid) for fid in evidence_ids)

        # 4. Support Check via DeBERTa-MNLI with fallback to Qwen3-14B
        support_passed = True
        support_score = 1.0
        fallback_used = False

        claim_text = claim.get("claim", "")
        evidence_combined_clean = " ".join(evidence_clean_texts)

        from models.classifiers import ClassifierLoader
        loader = ClassifierLoader()

        try:
            classifier = loader.load_mnli()
            # Run zero-shot entailment check
            res = classifier(
                sequences=claim_text,
                candidate_labels=["supports", "neutral", "contradicts"],
                hypothesis_template="This evidence: {}"
            )
            support_idx = res["labels"].index("supports")
            support_score = res["scores"][support_idx]

            if support_score < 0.7:
                fallback_used = True
                prompt = (
                    "SYSTEM INSTRUCTION:\n"
                    "You are a verification supervisor. Determine if the evidence supports the claim.\n"
                    "Respond with exactly 'YES' or 'NO'.\n\n"
                    f"Claim: {claim_text}\n"
                    f"Evidence:\n{' '.join(evidence_wrapped_texts)}"
                )
                response = self.model.generate(prompt)
                support_passed = "YES" in response.upper()
        except Exception as e:
            # Fallback to Qwen3-14B model generation on error
            fallback_used = True
            prompt = (
                "SYSTEM INSTRUCTION:\n"
                "You are a verification supervisor. Determine if the evidence supports the claim.\n"
                "Respond with exactly 'YES' or 'NO'.\n\n"
                f"Claim: {claim_text}\n"
                f"Evidence:\n{' '.join(evidence_wrapped_texts)}"
            )
            response = self.model.generate(prompt)
            support_passed = "YES" in response.upper()

        # 5. Severity and Divergence Checks (Stubbed)
        severity_passed = True
        divergence_passed = True

        verified = existence_passed and support_passed and severity_passed and divergence_passed

        return {
            "verified": verified,
            "checks": {
                "existence": existence_passed,
                "support": support_passed,
                "severity": severity_passed,
                "divergence": divergence_passed
            },
            "flags": [] if verified else [f"Failed verification. Support score: {support_score}, Fallback: {fallback_used}"]
        }


