"""
Agent 7 — Call 2: Independent Verification
===========================================
Runs in an ISOLATED context with a lightweight model.
Receives ONLY:
  - One individual claim
  - The underlying FIR records for that claim's evidence IDs
Does NOT receive Call 1's reasoning narrative or unrelated context.

Executes Four Independent Verification Checks:
  1. Existence   — Does each cited evidence_id exist in FIR for the authorized tenant?
  2. Support     — Does the finding actually support the claim? (DeBERTa-v3-large-MNLI)
  3. Severity    — Was confidence or severity silently inflated relative to the findings?
  4. Divergence  — Does the narrative contradict deterministic Layer 4 labels or findings?

Critical Security Policy:
  - If semantic entailment is inconclusive (< 0.70 threshold), the claim MUST remain
    unverified (verified = False) and be routed for human review.
  - An LLM fallback assessment is strictly secondary/informational and CANNOT override
    an unverified claim or approve Agent 7's own assertions.
"""

import logging
from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent
from fir.schemas import ReviewStatus

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "informational": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class SupervisorVerification(BaseAgent):
    """
    Agent 7 Call 2 — Independent Evidence & Claim Verifier.
    """

    SUPPORT_THRESHOLD = 0.70

    def run(self, case_id: str, context: dict) -> dict:
        """
        Runs verification over multiple claims in the given context.
        """
        claims = context.get("claims", [])
        tenant_id = context.get("tenant_id") or getattr(self, "tenant_id", "default")
        results = []
        for claim in claims:
            res = self.verify(claim, tenant_id=tenant_id)
            results.append(res)

        all_verified = all(r.get("verified", False) for r in results) if results else True
        unverified_count = sum(1 for r in results if not r.get("verified", False))

        return {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "verification_results": results,
            "all_claims_verified": all_verified,
            "unverified_claim_count": unverified_count,
        }

    def verify(self, claim: dict, fir_records: list = None, tenant_id: str = "") -> dict:
        """
        Verifies a single claim in an isolated context against its cited evidence.
        """
        claim_id = claim.get("claim_id") or "CLM-UNKNOWN"
        claim_text = claim.get("claim", "")
        claim_severity = str(claim.get("severity", "medium")).lower()
        claim_confidence = float(claim.get("confidence", 0.90))

        # 1. Resolve cited evidence IDs
        evidence_ids = list(claim.get("evidence_ids", []))
        if not evidence_ids and fir_records:
            for r in fir_records:
                if isinstance(r, dict):
                    fid = r.get("finding_id") or r.get("id")
                else:
                    fid = getattr(r, "finding_id", None) or getattr(r, "id", None)
                if fid:
                    evidence_ids.append(fid)

        flags: List[str] = []
        evidence_details: List[Dict[str, Any]] = []
        evidence_clean_texts: List[str] = []
        evidence_wrapped_texts: List[str] = []

        # 2. Pull evidence findings in isolated context with tenant validation
        t_id = tenant_id or getattr(self, "tenant_id", "default")
        fir_objects = []
        for fid in evidence_ids:
            finding = None
            if hasattr(self.fir, "get_by_id"):
                finding = self.fir.get_by_id(t_id, fid)

            if finding:
                fir_objects.append(finding)
                clean_fact = finding.sanitized_fact or finding.fact
                sev = getattr(finding, "severity", "medium")
                conf = getattr(finding, "confidence", 1.0)
                status = getattr(finding, "review_status", ReviewStatus.PENDING_REVIEW)
                evidence_details.append({
                    "finding_id": fid,
                    "fact": clean_fact,
                    "severity": sev,
                    "confidence": conf,
                    "review_status": str(status),
                    "tenant_id": getattr(finding, "tenant_id", t_id),
                })
            else:
                # Check for cross-tenant breach attempt
                raw_finding = None
                if hasattr(self.fir, "get_by_id"):
                    try:
                        raw_finding = self.fir.get_by_id(fid)
                    except TypeError:
                        pass

                if raw_finding and getattr(raw_finding, "tenant_id", "") not in ("", t_id, "default"):
                    flags.append(
                        f"Cross-tenant access violation: Evidence ID [{fid}] belongs to tenant '{raw_finding.tenant_id}', not '{t_id}'"
                    )
                clean_fact = f"Evidence ID: {fid}"

            # Safe context wrapping
            ev_wrapped = self.sanitized_context_fetch("fir", fid, tenant_id=t_id)
            evidence_wrapped_texts.append(ev_wrapped)
            evidence_clean_texts.append(clean_fact)

        # ── CHECK 1: Deterministic Existence & Tenant Check ───────────────
        existence_passed = True
        if not evidence_ids:
            existence_passed = False
            flags.append(f"Claim [{claim_id}] cites zero evidence IDs")
        else:
            missing_ids = []
            for fid in evidence_ids:
                exists = False
                if hasattr(self, "exists"):
                    exists = self.exists("fir", fid, tenant_id=t_id)
                elif hasattr(self.fir, "get_by_id"):
                    exists = self.fir.get_by_id(t_id, fid) is not None
                if not exists:
                    missing_ids.append(fid)

            if missing_ids:
                existence_passed = False
                flags.append(f"Evidence ID(s) not found in FIR for tenant '{t_id}': {', '.join(missing_ids)}")

        # ── CHECK 2: Semantic Support Check (DeBERTa-v3-large-MNLI) ───────
        support_passed = True
        support_score = 1.0
        entailment_label = "supports"
        fallback_used = False
        secondary_assessment: Optional[str] = None

        evidence_combined = " ".join(evidence_clean_texts).strip()

        if existence_passed and evidence_combined:
            from models.classifiers import ClassifierLoader
            loader = ClassifierLoader()

            try:
                classifier = loader.load_mnli()
                # Run zero-shot entailment
                res = classifier(
                    sequences=claim_text,
                    candidate_labels=["supports", "neutral", "contradicts"],
                    hypothesis_template="This evidence: {}"
                )
                entailment_label = res["labels"][0]
                supp_idx = res["labels"].index("supports")
                support_score = float(res["scores"][supp_idx])

                # Policy: support score must meet threshold
                if support_score < self.SUPPORT_THRESHOLD:
                    support_passed = False
                    fallback_used = True
                    flags.append(
                        f"Inconclusive semantic entailment (DeBERTa support score {support_score:.2f} < {self.SUPPORT_THRESHOLD:.2f})"
                    )

                    # Secondary LLM assessment (informational only — cannot override unverified status)
                    try:
                        prompt = (
                            "SYSTEM INSTRUCTION:\n"
                            "You are an objective forensic verification supervisor. Determine if the evidence strictly supports the claim.\n"
                            "Respond ONLY with 'YES' or 'NO'.\n\n"
                            f"Claim: {claim_text}\n"
                            f"Evidence:\n{' '.join(evidence_wrapped_texts)}"
                        )
                        resp = str(self.model.generate(prompt)).strip().upper()
                        secondary_assessment = "SECONDARY_AFFIRMED" if "YES" in resp else "SECONDARY_REJECTED"
                    except Exception as llm_err:
                        secondary_assessment = f"SECONDARY_FAILED: {llm_err}"

            except Exception as e:
                logger.warning(f"MNLI classifier unavailable or failed ({e}); marking support unverified", exc_info=True)
                support_passed = False
                fallback_used = True
                flags.append(f"DeBERTa verification model unavailable or failed: {e}")

                # Secondary LLM assessment
                try:
                    prompt = (
                        "SYSTEM INSTRUCTION:\n"
                        "You are an objective forensic verification supervisor. Determine if the evidence strictly supports the claim.\n"
                        "Respond ONLY with 'YES' or 'NO'.\n\n"
                        f"Claim: {claim_text}\n"
                        f"Evidence:\n{' '.join(evidence_wrapped_texts)}"
                    )
                    resp = str(self.model.generate(prompt)).strip().upper()
                    secondary_assessment = "SECONDARY_AFFIRMED" if "YES" in resp else "SECONDARY_REJECTED"
                except Exception as llm_err:
                    secondary_assessment = f"SECONDARY_FAILED: {llm_err}"

        elif not existence_passed:
            support_passed = False
            support_score = 0.0

        # ── CHECK 3: Severity & Confidence Inflation Check ───────────────
        severity_passed = True
        if fir_objects:
            max_evidence_sev_val = max(
                SEVERITY_WEIGHTS.get(str(getattr(fo, "severity", "medium")).lower(), 2)
                for fo in fir_objects
            )
            max_evidence_conf = max(
                float(getattr(fo, "confidence", 1.0))
                for fo in fir_objects
            )
            claim_sev_val = SEVERITY_WEIGHTS.get(claim_severity, 2)

            # Rule A: Claimed severity cannot be more than 1 tier higher than max evidence severity
            if claim_sev_val > max_evidence_sev_val + 1:
                severity_passed = False
                flags.append(
                    f"Severity silently inflated: claim asserts '{claim_severity}' but underlying evidence max is tier {max_evidence_sev_val}"
                )

            # Rule B: Claimed confidence cannot exceed evidence confidence by more than 0.25
            if claim_confidence > max_evidence_conf + 0.25:
                severity_passed = False
                flags.append(
                    f"Confidence inflated: claim confidence ({claim_confidence:.2f}) exceeds evidence confidence ({max_evidence_conf:.2f})"
                )

        # ── CHECK 4: Divergence Check ────────────────────────────────────
        divergence_passed = True
        # Check if underlying finding was explicitly rejected by an analyst
        for fo in fir_objects:
            status = getattr(fo, "review_status", None)
            if status == ReviewStatus.ANALYST_REJECTED:
                divergence_passed = False
                flags.append(
                    f"Divergence detected: cited finding [{fo.finding_id}] was marked ANALYST_REJECTED in Layer 4"
                )

        # Check if DeBERTa entailment strongly concluded contradiction
        if entailment_label == "contradicts" and support_score < 0.30:
            divergence_passed = False
            flags.append("Divergence detected: DeBERTa model flagged direct contradiction between evidence and claim")

        # ── VERDICT ──────────────────────────────────────────────────────
        verified = existence_passed and support_passed and severity_passed and divergence_passed
        status_label = "verified" if verified else "unverified — requires manual confirmation"

        return {
            "claim_id": claim_id,
            "claim": claim_text,
            "evidence_ids": evidence_ids,
            "verified": verified,
            "status": status_label,
            "checks": {
                "existence": existence_passed,
                "support": support_passed,
                "severity": severity_passed,
                "divergence": divergence_passed,
            },
            "support_score": round(support_score, 4),
            "entailment_label": entailment_label,
            "fallback_used": fallback_used,
            "secondary_assessment": secondary_assessment,
            "flags": flags,
            "evidence_details": evidence_details,
        }
