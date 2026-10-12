"""
Agent 7 — Call 2: Independent Verification
===========================================
Runs in an ISOLATED context with DeBERTa-v3-large-MNLI.
Receives ONLY:
  - One individual claim (as the NLI hypothesis)
  - The underlying FIR records for that claim's cited evidence IDs (as NLI premises)
Does NOT receive Call 1's reasoning narrative, entire report, or unrelated evidence.

Executes Four Independent Verification Checks:
  1. Existence   — Does each cited evidence_id exist in FIR for the authorized tenant and case?
  2. Support     — Does each cited finding actually support the claim? (DeBERTa-v3-large-MNLI)
  3. Severity    — Was confidence or severity silently inflated relative to the findings?
  4. Divergence  — Does the claim contradict deterministic Layer 4 labels or evidence?

Critical Security Policy:
  - Evidence text is passed as the NLI premise; claim text is passed as the hypothesis.
  - Multiple evidence records are evaluated individually; contradiction in any cited
    record flags a contradiction/divergence defect.
  - If semantic entailment is inconclusive (< 0.70 threshold) or model fails, the claim
    MUST remain unverified (verified = False) and be routed for human review.
  - An LLM fallback assessment is strictly secondary/informational and CANNOT override
    an unverified claim or approve Agent 7's own assertions.
"""

from __future__ import annotations

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
            res = self.verify(claim, tenant_id=tenant_id, case_id=case_id)
            results.append(res)

        # Empty claims or empty results cannot satisfy mandatory verification
        all_verified = bool(results) and all(r.get("verified", False) for r in results)
        unverified_count = sum(1 for r in results if not r.get("verified", False))

        return {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "verification_results": results,
            "all_claims_verified": all_verified,
            "unverified_claim_count": unverified_count,
            "claim_count": len(claims),
            "status": "COMPLETED" if (results and all_verified) else ("NEEDS_REVIEW" if results else "NO_CLAIMS"),
        }

    def verify(
        self,
        claim: dict,
        fir_records: Optional[list] = None,
        tenant_id: str = "",
        case_id: str = "",
    ) -> dict:
        """
        Verifies a single claim in an isolated context against its cited evidence.
        """
        claim_id = claim.get("claim_id") or "CLM-UNKNOWN"
        claim_text = (claim.get("claim") or claim.get("statement") or "").strip()
        claim_severity = str(claim.get("severity", "medium")).lower()

        # Validate confidence safely without assuming high defaults
        raw_conf = claim.get("confidence")
        claim_confidence: Optional[float] = None
        if raw_conf is not None:
            try:
                parsed_conf = float(raw_conf)
                if 0.0 <= parsed_conf <= 1.0:
                    claim_confidence = parsed_conf
            except (ValueError, TypeError):
                pass

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
        fir_objects: List[Any] = []
        existence_passed = True

        t_id = tenant_id or getattr(self, "tenant_id", "default")
        active_case = case_id or claim.get("case_id", "")

        # ── CHECK 1: Deterministic Existence & Scoped Retrieval ──────────
        if not evidence_ids:
            existence_passed = False
            flags.append(f"Claim [{claim_id}] cites zero evidence IDs")
        else:
            for fid in evidence_ids:
                finding = None
                if hasattr(self.fir, "get_by_id"):
                    try:
                        finding = self.fir.get_by_id(t_id, fid)
                    except Exception as lookup_err:
                        logger.warning(f"Error querying FIR for evidence {fid}: {lookup_err}")

                if finding is None:
                    # Check for cross-tenant breach attempt
                    raw_finding = None
                    if hasattr(self.fir, "get_by_id"):
                        try:
                            raw_finding = self.fir.get_by_id(fid)
                        except TypeError:
                            pass
                        except Exception:
                            pass

                    if raw_finding and getattr(raw_finding, "tenant_id", "") not in ("", t_id):
                        existence_passed = False
                        flags.append(
                            f"Evidence ID [{fid}] not found in FIR for tenant '{t_id}' (Cross-tenant access violation: belongs to tenant '{getattr(raw_finding, 'tenant_id', '')}')"
                        )
                    else:
                        existence_passed = False
                        flags.append(f"Evidence ID [{fid}] not found in FIR for tenant '{t_id}'")
                else:
                    # Every evidence record must be verified against authorized tenant and active case.
                    # Legacy or missing tenant metadata must not automatically authorize the record.
                    finding_tenant = getattr(finding, "tenant_id", None)
                    if not finding_tenant or (t_id and str(finding_tenant) != str(t_id)):
                        existence_passed = False
                        flags.append(
                            f"Tenant boundary violation: Evidence ID [{fid}] tenant '{finding_tenant}' does not match authorized tenant '{t_id}'"
                        )
                        continue

                    # Validate case boundary if finding specifies case_id or active_case is provided
                    finding_case = getattr(finding, "case_id", None)
                    if active_case and (not finding_case or str(finding_case) != str(active_case)):
                        existence_passed = False
                        flags.append(
                            f"Cross-case access violation: Evidence ID [{fid}] belongs to case '{finding_case}', not active case '{active_case}'"
                        )
                        continue

                    fir_objects.append(finding)
                    clean_fact = finding.sanitized_fact or finding.fact
                    sev = getattr(finding, "severity", "medium")
                    conf = getattr(finding, "confidence", None)
                    status = getattr(finding, "review_status", ReviewStatus.PENDING_REVIEW)
                    evidence_details.append({
                        "finding_id": fid,
                        "fact": clean_fact,
                        "severity": sev,
                        "confidence": conf,
                        "review_status": str(status),
                        "tenant_id": getattr(finding, "tenant_id", t_id),
                        "case_id": finding_case,
                    })

        # ── CHECK 2: Semantic Support Check (DeBERTa-v3-large-MNLI) ───────
        support_passed = False
        support_score = 0.0
        entailment_label = "unverified"
        evidence_evaluations: List[Dict[str, Any]] = []
        contradiction_detected = False
        fallback_used = False
        secondary_assessment: Optional[str] = None

        if existence_passed and evidence_details and claim_text:
            from models.classifiers import ClassifierLoader
            loader = ClassifierLoader()

            try:
                import re
                # 1. Evaluate individual evidence findings against the claim hypothesis
                for ev in evidence_details:
                    premise_fact = ev.get("fact", "")
                    if not premise_fact:
                        continue

                    nli_res = loader.classify_nli(premise=premise_fact, hypothesis=claim_text)
                    ent_score = float(nli_res.get("entailment", 0.0))
                    neut_score = float(nli_res.get("neutral", 0.0))
                    contra_score = float(nli_res.get("contradiction", 0.0))
                    top_label = str(nli_res.get("label", "neutral")).lower()

                    evidence_evaluations.append({
                        "finding_id": ev.get("finding_id"),
                        "premise": premise_fact,
                        "entailment": round(ent_score, 4),
                        "neutral": round(neut_score, 4),
                        "contradiction": round(contra_score, 4),
                        "label": top_label,
                    })

                    # Check for explicit contradiction
                    if contra_score >= 0.50 or (top_label == "contradiction" and contra_score > ent_score):
                        contradiction_detected = True
                        flags.append(
                            f"Contradiction detected: Evidence [{ev.get('finding_id')}] contradicts claim [{claim_id}] (contradiction score: {contra_score:.2f})"
                        )

                # 2. Defensible Compound Claim Aggregation Strategy:
                # Do NOT verify a compound claim just because one cited finding has the maximum entailment score.
                # Every material assertion/clause must demonstrate evidentiary support.
                raw_clauses = [c.strip() for c in re.split(r'(?<=[.!?])\s+|;\s*', claim_text) if c.strip()]
                clauses = raw_clauses if raw_clauses else [claim_text]

                all_clauses_supported = True
                clause_evaluations: List[Dict[str, Any]] = []

                if len(clauses) > 1:
                    # Evaluate each atomic clause across available evidence premises
                    combined_premise = " ".join(ev.get("fact", "") for ev in evidence_details if ev.get("fact"))
                    for cl in clauses:
                        cl_max_ent = 0.0
                        for ev in evidence_details:
                            pf = ev.get("fact", "")
                            if pf:
                                cl_res = loader.classify_nli(premise=pf, hypothesis=cl)
                                cl_ent = float(cl_res.get("entailment", 0.0))
                                cl_contra = float(cl_res.get("contradiction", 0.0))
                                if cl_contra >= 0.50:
                                    contradiction_detected = True
                                if cl_ent > cl_max_ent:
                                    cl_max_ent = cl_ent
                        if combined_premise:
                            cl_joint = loader.classify_nli(premise=combined_premise, hypothesis=cl)
                            cl_joint_ent = float(cl_joint.get("entailment", 0.0))
                            if float(cl_joint.get("contradiction", 0.0)) >= 0.50:
                                contradiction_detected = True
                            if cl_joint_ent > cl_max_ent:
                                cl_max_ent = cl_joint_ent

                        cl_supported = (cl_max_ent >= self.SUPPORT_THRESHOLD)
                        clause_evaluations.append({
                            "clause": cl,
                            "max_entailment": round(cl_max_ent, 4),
                            "supported": cl_supported,
                        })
                        if not cl_supported:
                            all_clauses_supported = False
                            flags.append(
                                f"Compound claim [{claim_id}] unsupported clause: '{cl}' score ({cl_max_ent:.2f}) < threshold ({self.SUPPORT_THRESHOLD:.2f})"
                            )

                if contradiction_detected:
                    support_passed = False
                    support_score = max((ev["entailment"] for ev in evidence_evaluations), default=0.0)
                    entailment_label = "contradiction"
                elif len(clauses) > 1 and not all_clauses_supported:
                    # Compound claim failed assertion support
                    support_passed = False
                    support_score = min((ce["max_entailment"] for ce in clause_evaluations), default=0.0)
                    entailment_label = "neutral"
                else:
                    # Evaluate combined premise for multi-evidence single-statement claims
                    if len(evidence_details) > 1:
                        combined_premise = " ".join(ev.get("fact", "") for ev in evidence_details if ev.get("fact"))
                        joint_res = loader.classify_nli(premise=combined_premise, hypothesis=claim_text)
                        joint_ent = float(joint_res.get("entailment", 0.0))
                        joint_contra = float(joint_res.get("contradiction", 0.0))
                        if joint_contra >= 0.50:
                            contradiction_detected = True
                            support_passed = False
                            support_score = joint_ent
                            entailment_label = "contradiction"
                        else:
                            # Use max of joint premise support and individual premise support
                            max_entailment = max(joint_ent, max((ev["entailment"] for ev in evidence_evaluations), default=0.0))
                            support_score = max_entailment
                            if max_entailment >= self.SUPPORT_THRESHOLD:
                                support_passed = True
                                entailment_label = "entailment"
                            else:
                                support_passed = False
                                entailment_label = "neutral"
                                fallback_used = True
                                flags.append(
                                    f"Inconclusive semantic entailment: Highest DeBERTa support score ({max_entailment:.2f}) < threshold ({self.SUPPORT_THRESHOLD:.2f})"
                                )
                    else:
                        max_entailment = max((ev["entailment"] for ev in evidence_evaluations), default=0.0)
                        support_score = max_entailment

                        if max_entailment >= self.SUPPORT_THRESHOLD:
                            support_passed = True
                            entailment_label = "entailment"
                        else:
                            support_passed = False
                            entailment_label = "neutral"
                            fallback_used = True
                            flags.append(
                                f"Inconclusive semantic entailment: Highest DeBERTa support score ({max_entailment:.2f}) < threshold ({self.SUPPORT_THRESHOLD:.2f})"
                            )

                    # Secondary LLM assessment (strictly informational, cannot override unverified status)
                    if not support_passed and not contradiction_detected:
                        try:
                            ev_wrapped_texts = [
                                self.sanitized_context_fetch("fir", fid, tenant_id=t_id)
                                for fid in evidence_ids
                            ]
                            prompt = (
                                "SYSTEM INSTRUCTION:\n"
                                "You are an objective forensic verification supervisor. Determine if the evidence strictly supports the claim.\n"
                                "Respond ONLY with 'YES' or 'NO'.\n\n"
                                f"Claim: {claim_text}\n"
                                f"Evidence:\n{' '.join(ev_wrapped_texts)}"
                            )
                            resp = str(self.model.generate(prompt)).strip().upper()
                            secondary_assessment = "SECONDARY_AFFIRMED" if "YES" in resp else "SECONDARY_REJECTED"
                        except Exception as llm_err:
                            secondary_assessment = f"SECONDARY_FAILED: {llm_err}"

            except Exception as e:
                logger.warning(f"MNLI classifier unavailable or failed ({e}); marking support unverified", exc_info=True)
                support_passed = False
                support_score = 0.0
                entailment_label = "unverified"
                fallback_used = True
                flags.append(f"DeBERTa verification model unavailable or failed: {e}")

                # Secondary LLM assessment
                try:
                    ev_wrapped_texts = [
                        self.sanitized_context_fetch("fir", fid, tenant_id=t_id)
                        for fid in evidence_ids
                    ]
                    prompt = (
                        "SYSTEM INSTRUCTION:\n"
                        "You are an objective forensic verification supervisor. Determine if the evidence strictly supports the claim.\n"
                        "Respond ONLY with 'YES' or 'NO'.\n\n"
                        f"Claim: {claim_text}\n"
                        f"Evidence:\n{' '.join(ev_wrapped_texts)}"
                    )
                    resp = str(self.model.generate(prompt)).strip().upper()
                    secondary_assessment = "SECONDARY_AFFIRMED" if "YES" in resp else "SECONDARY_REJECTED"
                except Exception as llm_err:
                    secondary_assessment = f"SECONDARY_FAILED: {llm_err}"

        elif not existence_passed:
            support_passed = False
            support_score = 0.0
            entailment_label = "unverified"
        elif not claim_text:
            support_passed = False
            support_score = 0.0
            entailment_label = "unverified"
            flags.append(f"Claim [{claim_id}] contains empty statement text")

        # ── CHECK 3: Severity & Confidence Inflation Check ───────────────
        severity_passed = True
        if claim_confidence is None:
            severity_passed = False
            flags.append(
                f"Missing model confidence: claim [{claim_id}] lacks explicit confidence score; cannot verify without model confidence"
            )
        elif fir_objects:
            max_evidence_sev_val = max(
                SEVERITY_WEIGHTS.get(str(getattr(fo, "severity", "medium")).lower(), 2)
                for fo in fir_objects
            )
            valid_confidences = [
                float(getattr(fo, "confidence"))
                for fo in fir_objects
                if getattr(fo, "confidence", None) is not None
            ]
            max_evidence_conf = max(valid_confidences) if valid_confidences else None
            claim_sev_val = SEVERITY_WEIGHTS.get(claim_severity, 2)

            # Rule A: Claimed severity cannot be more than 1 tier higher than max evidence severity
            if claim_sev_val > max_evidence_sev_val + 1:
                severity_passed = False
                flags.append(
                    f"Severity silently inflated: claim asserts '{claim_severity}' but underlying evidence max is tier {max_evidence_sev_val}"
                )

            # Rule B: Claimed confidence cannot exceed evidence confidence by more than 0.25
            if max_evidence_conf is not None:
                if claim_confidence > max_evidence_conf + 0.25:
                    severity_passed = False
                    flags.append(
                        f"Confidence inflated: claim confidence ({claim_confidence:.2f}) exceeds evidence confidence ({max_evidence_conf:.2f})"
                    )

        # ── CHECK 4: Divergence Check ────────────────────────────────────
        divergence_passed = True
        # Check if underlying finding was explicitly rejected by an analyst in Layer 4
        for fo in fir_objects:
            status = getattr(fo, "review_status", None)
            if status == ReviewStatus.ANALYST_REJECTED:
                divergence_passed = False
                flags.append(
                    f"Divergence detected: cited finding [{fo.finding_id}] was marked ANALYST_REJECTED in Layer 4"
                )

        if contradiction_detected:
            divergence_passed = False

        # ── VERDICT ──────────────────────────────────────────────────────
        verified = existence_passed and support_passed and severity_passed and divergence_passed
        status_label = "verified" if verified else "unverified — requires manual confirmation"

        if verified:
            detailed_status = "supported"
        elif not existence_passed:
            detailed_status = "invalid_or_missing_evidence"
        elif contradiction_detected or not divergence_passed:
            detailed_status = "contradicted"
        elif not support_passed:
            detailed_status = "insufficient_evidence"
        elif not severity_passed:
            detailed_status = "severity_inflated"
        else:
            detailed_status = "unverified"

        return {
            "claim_id": claim_id,
            "claim": claim_text,
            "evidence_ids": evidence_ids,
            "verified": verified,
            "status": status_label,
            "verification_status": detailed_status,
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
            "evidence_evaluations": evidence_evaluations,
            "model_metadata": {
                "model": "MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli",
                "threshold": self.SUPPORT_THRESHOLD,
            },
        }
