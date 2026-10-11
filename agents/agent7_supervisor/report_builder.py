"""
Agent 7 — Report Builder Module
===============================
Deterministic report assembly and rendering module for Agent 7.
Builds the 3 required report types:
  1. Analyst Report       (in-depth technical, IOCs, MITRE, timeline, verified claims)
  2. Customer Report      (clear incident overview, impact, recovery checklist)
  3. Executive Summary    (strategic risk, key findings, immediate actions)

Stamps every report package with legal defensibility metadata:
  - Model name & actual execution statuses
  - Prompt template version
  - Retrieval corpus snapshot ID (or explicit 'unavailable')
  - Deterministic execution timestamp
  - Authoritative chain-of-custody status (or 'not_verified' / False)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from report_generation.generator import ReportGenerator


class SupervisorReportBuilder:
    """
    Renders deterministic multi-audience report packages for Agent 7.
    """

    PROMPT_TEMPLATE_VERSION = "v2.4-supervisor"
    DEFAULT_MODEL_NAME = "Qwen3-8B / DeBERTa-v3-large-MNLI"

    def __init__(self, generator: Optional[ReportGenerator] = None):
        self.generator = generator or ReportGenerator()

    def build_report_package(
        self,
        case_id: str,
        tenant_id: str,
        synthesis: Dict[str, Any],
        verification_results: List[Dict[str, Any]],
        confidence_gate: Dict[str, Any],
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Builds and renders the complete report package across all audiences and formats.
        Only stamps metadata that can be established from actual runtime; never fabricates hashes.
        """
        extra = extra_context or {}
        now_iso = datetime.now(timezone.utc).isoformat()

        # Chain of custody must be evidence-based or explicitly marked not_verified
        coc_verified = bool(extra.get("chain_of_custody_verified", False))
        coc_status = extra.get("chain_of_custody_status") or ("verified" if coc_verified else "not_verified")

        # Legitimate metadata from runtime context (no fabricated hashes)
        metadata = {
            "model_name": extra.get("model_name") or self.DEFAULT_MODEL_NAME,
            "synthesis_model": extra.get("synthesis_model", "Qwen3-8B"),
            "verification_model": extra.get("verification_model", "MoritzLaurer/DeBERTa-v3-large-MNLI"),
            "model_version_hash": extra.get("model_version_hash") or "unavailable",
            "prompt_template_version": self.PROMPT_TEMPLATE_VERSION,
            "retrieval_corpus_snapshot_id": extra.get("corpus_snapshot_id") or "unavailable",
            "timestamp": now_iso,
            "case_id": case_id,
            "tenant_id": tenant_id,
            "report_version": extra.get("report_version", "1.0"),
            "review_status": confidence_gate.get("route", "senior_dual"),
            "legal_chain_of_custody_verified": coc_verified,
            "legal_chain_of_custody_status": coc_status,
        }

        # 1. Analyst Report Data
        analyst_data = self._build_analyst_payload(
            case_id, tenant_id, synthesis, verification_results, confidence_gate, metadata, extra
        )

        # 2. Customer Report Data
        customer_data = self._build_customer_payload(
            case_id, tenant_id, synthesis, verification_results, confidence_gate, metadata, extra
        )

        # 3. Executive Summary Data
        executive_data = self._build_executive_payload(
            case_id, tenant_id, synthesis, verification_results, confidence_gate, metadata, extra
        )

        # Render reports in HTML and JSON formats
        rendered_reports = {
            "analyst": {
                "json": self.generator.generate(analyst_data, format="json"),
                "html": self.generator.generate(analyst_data, format="html"),
                "data": analyst_data,
            },
            "customer": {
                "json": self.generator.generate(customer_data, format="json"),
                "html": self.generator.generate(customer_data, format="html"),
                "data": customer_data,
            },
            "executive": {
                "json": self.generator.generate(executive_data, format="json"),
                "html": self.generator.generate(executive_data, format="html"),
                "data": executive_data,
            },
        }

        return {
            "metadata": metadata,
            "rendered": rendered_reports,
        }

    def _build_analyst_payload(
        self,
        case_id: str,
        tenant_id: str,
        synthesis: Dict[str, Any],
        verification_results: List[Dict[str, Any]],
        confidence_gate: Dict[str, Any],
        metadata: Dict[str, Any],
        extra: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Assembles data payload for the technical Analyst Report."""
        findings = []
        for vr in verification_results:
            findings.append({
                "finding_id": vr.get("claim_id"),
                "fact": vr.get("claim"),
                "severity": vr.get("severity", "medium"),
                "confidence": float(vr.get("support_score", 0.0)),
                "review_status": "verified" if vr.get("verified") else "unverified",
                "evidence_reference": vr.get("evidence_ids", []),
                "verification_status": vr.get("status"),
                "checks": vr.get("checks", {}),
                "flags": vr.get("flags", []),
            })

        timeline = synthesis.get("attack_timeline") or extra.get("timeline") or []
        mitre_matrix = synthesis.get("mitre_matrix") or []

        raw_conf = synthesis.get("confidence_score")
        conf_score = float(raw_conf) if raw_conf is not None else 0.0

        return {
            "report_type": "Analyst Report",
            "case_id": case_id,
            "tenant_id": tenant_id,
            "generated_at": metadata["timestamp"],
            "metadata": metadata,
            "investigation_confidence_score": conf_score,
            "review_route": confidence_gate.get("route", "senior_dual"),
            "review_reasons": confidence_gate.get("reasons", []),
            "attention_items": confidence_gate.get("attention_items", []),
            "executive_summary": synthesis.get("executive_summary", ""),
            "incident_narrative": synthesis.get("incident_narrative", ""),
            "findings": findings,
            "timeline": timeline,
            "mitre_matrix": mitre_matrix,
            "conflicts_resolved": synthesis.get("conflicts_resolved", []),
            "evidence_files": extra.get("evidence_files", []),
            "technical_recommendations": extra.get(
                "technical_recommendations",
                [
                    "Review unverified findings in forensic repository before proceeding.",
                    "Verify cited evidence chain of custody and cryptographic hashes.",
                ]
            ),
        }

    def _build_customer_payload(
        self,
        case_id: str,
        tenant_id: str,
        synthesis: Dict[str, Any],
        verification_results: List[Dict[str, Any]],
        confidence_gate: Dict[str, Any],
        metadata: Dict[str, Any],
        extra: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Assembles data payload for the Customer Report (safe, high-level, no internal raw logs)."""
        return {
            "report_type": "Customer Incident Report",
            "case_id": case_id,
            "tenant_id": tenant_id,
            "generated_at": metadata["timestamp"],
            "metadata": metadata,
            "incident_overview": synthesis.get("executive_summary", "Forensic assessment in progress."),
            "entry_vector": extra.get("entry_vector") or "Not established by the available evidence",
            "adversary_actions": synthesis.get("incident_narrative", ""),
            "data_affected": extra.get("data_affected") or "Not established by the available evidence",
            "risk_level": extra.get("risk_level") or "Requires analyst review",
            "recovery_checklist": extra.get(
                "recovery_checklist",
                [
                    "Perform analyst review of cited forensic evidence.",
                    "Await senior analyst sign-off before modifying host configurations.",
                ]
            ),
            "recommendations": extra.get(
                "recommendations",
                [
                    "Maintain system isolation pending full forensic verification.",
                ]
            ),
            "findings": [
                {
                    "finding_id": vr.get("claim_id"),
                    "fact": vr.get("claim"),
                    "severity": vr.get("severity", "medium"),
                    "confidence": float(vr.get("support_score", 0.0)),
                    "review_status": "verified" if vr.get("verified") else "unverified",
                    "evidence_reference": vr.get("evidence_ids", []),
                }
                for vr in verification_results
            ],
        }

    def _build_executive_payload(
        self,
        case_id: str,
        tenant_id: str,
        synthesis: Dict[str, Any],
        verification_results: List[Dict[str, Any]],
        confidence_gate: Dict[str, Any],
        metadata: Dict[str, Any],
        extra: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Assembles data payload for Executive Summary."""
        raw_conf = synthesis.get("confidence_score")
        conf_score = float(raw_conf) if raw_conf is not None else 0.0

        return {
            "report_type": "Executive Incident Summary",
            "case_id": case_id,
            "tenant_id": tenant_id,
            "generated_at": metadata["timestamp"],
            "metadata": metadata,
            "incident_title": f"Digital Forensic Incident Investigation — Case {case_id}",
            "high_level_incident": synthesis.get("executive_summary", "Incident investigation pending formal review."),
            "key_findings": [vr.get("claim") for vr in verification_results if vr.get("verified")][:5],
            "investigation_confidence": conf_score,
            "review_route": confidence_gate.get("route", "senior_dual"),
            "risk": extra.get("risk") or "Not established by the available evidence",
            "impact": extra.get("impact") or "Not established by the available evidence",
            "recommended_actions": extra.get(
                "recommended_actions",
                [
                    "Review findings with lead forensic examiner.",
                    "Await completion of formal senior verification.",
                ]
            ),
            "findings": [
                {
                    "finding_id": vr.get("claim_id"),
                    "fact": vr.get("claim"),
                    "severity": vr.get("severity", "medium"),
                    "confidence": float(vr.get("support_score", 0.0)),
                    "review_status": "verified" if vr.get("verified") else "unverified",
                    "evidence_reference": vr.get("evidence_ids", []),
                }
                for vr in verification_results
            ],
        }
