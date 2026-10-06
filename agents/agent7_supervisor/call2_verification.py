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
import re
from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

class SupervisorVerification(BaseAgent):
    def run(self, case_id: str, context: dict) -> dict:
        raise NotImplementedError("Use verify() method for independent verification.")

    def verify(self, claim: dict, fir_records: list = None) -> dict:
        """Verify a claim only against explicitly scoped authoritative FIR records."""
        if not isinstance(claim, dict):
            return self._failed("Claim must be a mapping.")
        case_id = str(claim.get("case_id") or "")
        tenant_id = str(claim.get("tenant_id") or self.tenant_id or "")
        evidence_ids = [str(value) for value in claim.get("evidence_ids", [])]
        if not case_id or not tenant_id or not evidence_ids:
            return self._failed("Case, tenant, and non-empty evidence_ids are required.")
        if self.tenant_id and tenant_id != self.tenant_id:
            return self._failed("Claim tenant is outside the verifier scope.")
        if len(set(evidence_ids)) != len(evidence_ids):
            return self._failed("Duplicate evidence references are not permitted.")

        supplied = {
            str((r.get("finding_id") or r.get("id")) if isinstance(r, dict)
                else (getattr(r, "finding_id", None) or getattr(r, "id", None))): r
            for r in (fir_records or [])
        }
        authoritative = {}
        for fid in evidence_ids:
            record = self.fir.get_by_id(tenant_id, fid) if self.fir is not None else None
            if record is None:
                return self._failed(f"Evidence {fid} could not be resolved.")
            record_case = str(getattr(record, "case_id", None) or (record.get("case_id") if isinstance(record, dict) else ""))
            record_tenant = str(getattr(record, "tenant_id", None) or (record.get("tenant_id") if isinstance(record, dict) else ""))
            record_id = str(getattr(record, "finding_id", None) or (record.get("finding_id") if isinstance(record, dict) else ""))
            if record_id != fid or record_case != case_id or record_tenant != tenant_id:
                return self._failed(f"Evidence {fid} is outside the requested scope.")
            if supplied and supplied.get(fid) is not None:
                supplied_record = supplied[fid]
                supplied_case = str(getattr(supplied_record, "case_id", None) or (supplied_record.get("case_id") if isinstance(supplied_record, dict) else ""))
                supplied_tenant = str(getattr(supplied_record, "tenant_id", None) or (supplied_record.get("tenant_id") if isinstance(supplied_record, dict) else ""))
                if supplied_case != case_id or supplied_tenant != tenant_id:
                    return self._failed(f"Supplied evidence {fid} is outside the requested scope.")
            authoritative[fid] = record

        # Pull only the already scope-validated authoritative records into context.
        evidence_wrapped_texts = []
        evidence_clean_texts = []
        for fid in evidence_ids:
            ev_wrapped = self.sanitized_context_fetch("fir", fid, tenant_id=tenant_id)
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
        existence_passed = bool(authoritative) and len(authoritative) == len(evidence_ids)

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
                sequences=f"Authoritative evidence:\n{evidence_combined_clean}",
                candidate_labels=["supports", "neutral", "contradicts"],
                hypothesis_template=f"This evidence supports the claim: {claim_text}. Assessment: {{}}",
            )
            support_idx = res["labels"].index("supports")
            support_score = res["scores"][support_idx]

            has_anchor = self._claim_has_evidence_anchor(
                claim_text, evidence_combined_clean
            )
            if not has_anchor:
                # A model score cannot replace deterministic grounding.
                support_passed = False
            elif support_score < 0.7:
                fallback_used = True
                prompt = (
                    "SYSTEM INSTRUCTION:\n"
                    "You are a verification supervisor. Determine if the evidence supports the claim.\n"
                    "Respond with exactly 'YES' or 'NO'.\n\n"
                    f"Claim: {claim_text}\n"
                    f"Evidence:\n{' '.join(evidence_wrapped_texts)}"
                )
                response = self.model.generate(prompt)
                support_passed = response.strip().upper() == "YES"
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
            support_passed = response.strip().upper() == "YES"

        severity_passed = self._severity_supported(claim, authoritative.values())
        divergence_passed = self._divergence_supported(claim)

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

    @staticmethod
    def _failed(message: str) -> dict:
        return {
            "verified": False,
            "checks": {"existence": False, "support": False, "severity": False, "divergence": False},
            "flags": [message],
        }

    @staticmethod
    def _severity_supported(claim: dict, records) -> bool:
        requested = claim.get("severity")
        if requested is None:
            return True
        values = {
            str(getattr(record, "severity", None) or (record.get("severity") if isinstance(record, dict) else "")).lower()
            for record in records
        }
        return bool(values) and str(requested).lower() in values

    @staticmethod
    def _divergence_supported(claim: dict) -> bool:
        expected = claim.get("deterministic_label")
        narrative = claim.get("label")
        return expected is None or narrative is None or str(expected).lower() == str(narrative).lower()

    @staticmethod
    def _claim_has_evidence_anchor(claim: str, evidence: str) -> bool:
        """Require a deterministic lexical anchor before accepting model support."""
        words = {
            word.lower()
            for word in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{2,}", claim)
            if word.lower() not in {"the", "and", "with", "from", "that", "this", "was", "are"}
        }
        evidence_lower = evidence.lower()
        return bool(words) and any(word in evidence_lower for word in words)
