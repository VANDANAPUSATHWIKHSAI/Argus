"""
Agent 7 — Call 1: Synthesis
===========================
Takes full investigation context from upstream agents:
  - Agent 3: Attack Reconstruction (kill-chain, infection paths)
  - Agent 4: Malware Behavior (capabilities, dropped artifacts)
  - Agent 5b: Campaign Similarity (cluster analysis)
  - Agent 6: Impact Assessment (compromised hosts/data, business impact)
Plus supporting context from Agent 1 (intake/evidence), Agent 2 (correlation),
and Agent 5a (threat intelligence).

Performs:
  - Cross-agent evidence fusion & deduplication
  - Conflict resolution between findings
  - Timeline generation
  - Structured, cited claim generation with attached evidence IDs
  - Investigation Confidence Score calculation
"""

from __future__ import annotations

import json
import re
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent
from agents.agent7_supervisor.schemas import StructuredClaim, InvestigationSynthesis

logger = logging.getLogger(__name__)


SUPERVISOR_SYNTHESIS_SYSTEM_PROMPT = """You are the Senior Cybersecurity Supervisor Agent for Project ARGUS.
Your task is to synthesize the comprehensive investigative outputs from upstream forensic agents into an authoritative, legally defensible, evidence-backed case synthesis.

You MUST produce a valid JSON object matching the following structure:
{
  "executive_summary": "High-level summary of the incident (entry vector, impact, risk)",
  "incident_narrative": "Detailed narrative of attack progression from initial access to objective",
  "claims": [
    {
      "claim_id": "CLM-001",
      "claim": "Clear factual assertion about the adversary activity",
      "evidence_ids": ["FIR-XXXXX"],
      "severity": "critical" | "high" | "medium" | "low" | "informational",
      "is_attribution": true | false,
      "confidence": 0.95,
      "mitre_tactics": ["Initial Access"],
      "mitre_techniques": ["T1566.001"]
    }
  ],
  "attack_timeline": [
    {
      "timestamp": "ISO-8601 UTC timestamp",
      "stage": "Initial Access",
      "summary": "Event summary",
      "source_tool": "Tool name",
      "evidence_id": "FIR-XXXXX"
    }
  ],
  "conflicts_resolved": [
    {
      "conflict_description": "Description of conflicting evidence/agent reports",
      "resolution": "Reasoned decision based on deterministic evidence priority",
      "evidence_basis": ["FIR-XXXXX"]
    }
  ],
  "confidence_score": 0.92
}

RULES:
1. Every claim MUST be backed by at least one valid FIR evidence ID.
2. Resolve any contradictory timing, malware attribution, or event sequences.
3. If threat actor attribution is claimed, set is_attribution to true.
4. Confidence score must strictly reflect the evidence grounding (0.0 to 1.0).
5. Output ONLY valid JSON. No surrounding markdown fences or conversation.
"""


class SupervisorSynthesis(BaseAgent):
    """
    Agent 7 Call 1 — Primary Investigation Synthesizer.
    """

    def run(self, case_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes Call 1 synthesis across all upstream investigative outputs.
        """
        ctx = context or {}
        tenant_id = ctx.get("tenant_id") or getattr(self, "tenant_id", "default")
        agent_outputs = ctx.get("agent_outputs") or {}
        evidence_ids = list(ctx.get("evidence_ids") or [])

        # Gather relevant FIR findings if evidence_ids supplied
        evidence_snippets = []
        for eid in evidence_ids:
            try:
                ev_text = self.sanitized_context_fetch("fir", eid, tenant_id=tenant_id)
                evidence_snippets.append(ev_text)
            except Exception as e:
                logger.debug(f"Could not fetch FIR finding {eid}: {e}")

        # Assemble prompt payload
        prompt_context = {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "agent3_attack_reconstruction": agent_outputs.get("agent3") or ctx.get("agent3"),
            "agent4_malware_behavior": agent_outputs.get("agent4") or ctx.get("agent4"),
            "agent5b_campaign_similarity": agent_outputs.get("agent5b") or ctx.get("agent5b"),
            "agent6_impact_assessment": agent_outputs.get("agent6") or ctx.get("agent6"),
            "agent1_evidence_intel": agent_outputs.get("agent1") or ctx.get("agent1"),
            "agent2_correlation": agent_outputs.get("agent2") or ctx.get("agent2"),
            "agent5a_threat_intel": agent_outputs.get("agent5a") or ctx.get("agent5a"),
            "cited_evidence": evidence_snippets[:50],
        }

        # Filter out None values
        prompt_context_clean = {k: v for k, v in prompt_context.items() if v is not None}

        # Format user prompt
        user_prompt = (
            f"Synthesize the following digital forensic outputs for Case '{case_id}':\n\n"
            f"{json.dumps(prompt_context_clean, indent=2, default=str)[:8000]}"
        )

        full_prompt = (
            f"{SUPERVISOR_SYNTHESIS_SYSTEM_PROMPT}\n\n"
            f"USER INPUT:\n{user_prompt}\n\n"
            f"ASSISTANT RESPONSE (JSON only):"
        )

        response_text = ""
        model_error = None
        try:
            response_text = self.model.generate(full_prompt)
        except Exception as e:
            logger.error(f"LLM generation failed in SupervisorSynthesis: {e}", exc_info=True)
            model_error = f"SYNTHESIS_MODEL_FAILED: {str(e)}"

        parsed = self._parse_synthesis_response(response_text, case_id, tenant_id, evidence_ids)
        if model_error:
            parsed["synthesis_status"] = "FAILED"
            parsed["synthesis_error"] = model_error
        return parsed

    def _parse_synthesis_response(
        self,
        raw_text: str,
        case_id: str,
        tenant_id: str,
        fallback_evidence_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Parses and validates LLM synthesis response into structured dict.
        Never fabricates claims, evidence IDs, or artificial confidence scores.
        """
        data = None
        synthesis_error = None
        if raw_text is not None:
            cleaned = str(raw_text).strip()
            # Strip markdown json block if present
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned)
            try:
                data = json.loads(cleaned)
            except Exception:
                # Attempt regex search for JSON object
                match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
                if match:
                    try:
                        data = json.loads(match.group(1))
                    except Exception:
                        pass

        if not isinstance(data, dict):
            logger.warning(
                "Synthesis LLM response could not be parsed as valid JSON; returning typed incomplete synthesis."
            )
            synthesis_error = "MALFORMED_OUTPUT: Synthesis model output could not be parsed as JSON."
            data = {
                "executive_summary": "Investigation synthesis unavailable: Model output could not be parsed as structured JSON.",
                "incident_narrative": "No structured claims could be extracted due to synthesis output parsing failure.",
                "claims": [],
                "attack_timeline": [],
                "conflicts_resolved": [],
                "confidence_score": 0.0,
            }

        # Normalize claims without fabricating evidence references or scores
        claims_raw = data.get("claims") or []
        normalized_claims = []
        for idx, c in enumerate(claims_raw, start=1):
            if isinstance(c, dict):
                cid = c.get("claim_id") or f"CLM-{idx:03d}"
                ctext = (c.get("claim") or c.get("statement") or "").strip()
                if not ctext:
                    continue
                # Cited evidence IDs must come from the actual claim, not invented
                eids = c.get("evidence_ids")
                if eids is None:
                    eids = []
                elif not isinstance(eids, list):
                    eids = [str(eids)]

                sev = str(c.get("severity") or "medium").lower()
                if sev not in ("critical", "high", "medium", "low", "informational"):
                    sev = "medium"

                # Parse confidence safely without defaulting to 0.90 or treating absent as 0.0
                c_conf = None
                if c.get("confidence") is not None:
                    try:
                        val = float(c["confidence"])
                        c_conf = max(0.0, min(1.0, val))
                    except (ValueError, TypeError):
                        c_conf = None

                normalized_claims.append({
                    "claim_id": cid,
                    "claim": ctext,
                    "evidence_ids": [str(eid).strip() for eid in eids if str(eid).strip()],
                    "severity": sev,
                    "is_attribution": bool(c.get("is_attribution", False)),
                    "confidence": c_conf,
                    "mitre_tactics": list(c.get("mitre_tactics") or []),
                    "mitre_techniques": list(c.get("mitre_techniques") or []),
                })

        # CRITICAL: If no claims were generated or parsed, DO NOT invent a fallback claim.
        # Leave normalized_claims as [] and mark incomplete.

        raw_score = data.get("confidence_score")
        confidence_score = 0.0
        if raw_score is not None:
            try:
                confidence_score = float(raw_score)
                confidence_score = max(0.0, min(1.0, confidence_score))
            except (ValueError, TypeError):
                confidence_score = 0.0

        status = "FAILED" if synthesis_error else ("COMPLETED" if normalized_claims else "NO_CLAIMS")

        return {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "executive_summary": data.get("executive_summary", ""),
            "incident_narrative": data.get("incident_narrative", ""),
            "claims": normalized_claims,
            "attack_timeline": list(data.get("attack_timeline") or []),
            "conflicts_resolved": list(data.get("conflicts_resolved") or []),
            "confidence_score": confidence_score,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "synthesis_status": status,
            "synthesis_error": synthesis_error,
        }
