"""
Investigation Severity Score (ISS) Engine
===========================================
Calculates ARGUS's investigation-level Impact Severity Score (ISS).

Core Architectural Rules:
  1. ISS is ARGUS's investigation-level impact and business risk measure.
  2. CVSS is a deterministic technical input component to ISS, NOT synonymous with ISS.
  3. Evaluates 6 distinct, weighted forensic dimensions with explicit evidence citations.
  4. Never allows LLMs or agents to override deterministic scoring inputs.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Any, Optional, Set
from agents.agent6_impact_assessment.schemas import (
    ISSAssessment,
    ISSFactorScore,
    ISSSeverity,
    CVSSAssessment,
    AffectedAsset,
    AssetCriticality
)

logger = logging.getLogger(__name__)


def derive_iss_severity(score: float) -> ISSSeverity:
    """Derives qualitative severity from ISS score."""
    if score == 0.0:
        return ISSSeverity.NONE
    elif 0.1 <= score <= 3.9:
        return ISSSeverity.LOW
    elif 4.0 <= score <= 6.9:
        return ISSSeverity.MEDIUM
    elif 7.0 <= score <= 8.9:
        return ISSSeverity.HIGH
    elif 9.0 <= score <= 10.0:
        return ISSSeverity.CRITICAL
    return ISSSeverity.MEDIUM


class ISSCalculator:
    """
    Deterministic multi-factor Investigation Severity Score calculator.
    """

    # Weights sum strictly to 1.00
    WEIGHTS = {
        "asset_criticality":        0.25,
        "data_impact":              0.20,
        "system_integrity":         0.20,
        "operational_availability": 0.15,
        "scope_lateral_movement":   0.10,
        "technical_vulnerability":  0.10,
    }

    @classmethod
    def calculate_iss(
        cls,
        affected_assets: List[AffectedAsset],
        cvss_assessment: Optional[CVSSAssessment] = None,
        agent3_output: Optional[Dict[str, Any]] = None,
        agent4_output: Optional[Dict[str, Any]] = None,
        fir_findings: Optional[List[Any]] = None
    ) -> ISSAssessment:
        agent3_output = agent3_output or {}
        agent4_output = agent4_output or {}
        fir_findings = fir_findings or []

        factor_breakdown: Dict[str, ISSFactorScore] = {}
        all_contributing_evidence_ids: Set[str] = set()

        # ── 1. Asset Criticality Factor (Weight: 0.25) ────────────────────────
        asset_score, asset_desc, asset_eids = cls._compute_asset_criticality_factor(affected_assets)
        w_asset = cls.WEIGHTS["asset_criticality"]
        factor_breakdown["asset_criticality"] = ISSFactorScore(
            factor_name="Asset Criticality & Enterprise Exposure",
            weight=w_asset,
            raw_score=asset_score,
            weighted_score=round(asset_score * w_asset, 2),
            description=asset_desc,
            evidence_ids=asset_eids
        )
        all_contributing_evidence_ids.update(asset_eids)

        # ── 2. Data Impact & Confidentiality Factor (Weight: 0.20) ───────────
        data_score, data_desc, data_eids = cls._compute_data_impact_factor(agent3_output, agent4_output, fir_findings)
        w_data = cls.WEIGHTS["data_impact"]
        factor_breakdown["data_impact"] = ISSFactorScore(
            factor_name="Data Compromise & Confidentiality Exposure",
            weight=w_data,
            raw_score=data_score,
            weighted_score=round(data_score * w_data, 2),
            description=data_desc,
            evidence_ids=data_eids
        )
        all_contributing_evidence_ids.update(data_eids)

        # ── 3. System Integrity & Tampering Factor (Weight: 0.20) ────────────
        integ_score, integ_desc, integ_eids = cls._compute_system_integrity_factor(agent4_output, fir_findings)
        w_integ = cls.WEIGHTS["system_integrity"]
        factor_breakdown["system_integrity"] = ISSFactorScore(
            factor_name="System Integrity & Persistence Depth",
            weight=w_integ,
            raw_score=integ_score,
            weighted_score=round(integ_score * w_integ, 2),
            description=integ_desc,
            evidence_ids=integ_eids
        )
        all_contributing_evidence_ids.update(integ_eids)

        # ── 4. Operational Availability & Disruption Factor (Weight: 0.15) ────
        avail_score, avail_desc, avail_eids = cls._compute_availability_factor(fir_findings)
        w_avail = cls.WEIGHTS["operational_availability"]
        factor_breakdown["operational_availability"] = ISSFactorScore(
            factor_name="Operational Availability & Service Downtime",
            weight=w_avail,
            raw_score=avail_score,
            weighted_score=round(avail_score * w_avail, 2),
            description=avail_desc,
            evidence_ids=avail_eids
        )
        all_contributing_evidence_ids.update(avail_eids)

        # ── 5. Scope & Lateral Movement Factor (Weight: 0.10) ──────────────────
        scope_score, scope_desc, scope_eids = cls._compute_scope_factor(agent3_output, affected_assets)
        w_scope = cls.WEIGHTS["scope_lateral_movement"]
        factor_breakdown["scope_lateral_movement"] = ISSFactorScore(
            factor_name="Scope of Compromise & Lateral Movement",
            weight=w_scope,
            raw_score=scope_score,
            weighted_score=round(scope_score * w_scope, 2),
            description=scope_desc,
            evidence_ids=scope_eids
        )
        all_contributing_evidence_ids.update(scope_eids)

        # ── 6. Technical Vulnerability Severity (CVSS baseline) (Weight: 0.10) ─
        tech_score, tech_desc, tech_eids = cls._compute_technical_vulnerability_factor(cvss_assessment)
        w_tech = cls.WEIGHTS["technical_vulnerability"]
        factor_breakdown["technical_vulnerability"] = ISSFactorScore(
            factor_name="Technical Vulnerability Severity (CVSS Baseline)",
            weight=w_tech,
            raw_score=tech_score,
            weighted_score=round(tech_score * w_tech, 2),
            description=tech_desc,
            evidence_ids=tech_eids
        )
        all_contributing_evidence_ids.update(tech_eids)

        # Aggregate weighted score
        total_raw = sum(f.weighted_score for f in factor_breakdown.values())
        final_iss = min(10.0, max(0.0, round(total_raw, 1)))
        severity = derive_iss_severity(final_iss)

        summary = (
            f"ARGUS Investigation Severity Score (ISS) calculated at {final_iss}/10.0 ({severity.value}). "
            f"Primary impact drivers: {cls._identify_top_drivers(factor_breakdown)}."
        )

        return ISSAssessment(
            iss_score=final_iss,
            severity=severity,
            factor_breakdown=factor_breakdown,
            contributing_evidence_ids=sorted(list(all_contributing_evidence_ids)),
            executive_summary=summary
        )

    # ── Factor Evaluators ──────────────────────────────────────────────────────

    @classmethod
    def _compute_asset_criticality_factor(
        cls,
        assets: List[AffectedAsset]
    ) -> (float, str, List[str]):
        if not assets:
            return (2.0, "No specific enterprise assets registered; baseline host assumed.", [])

        eids: List[str] = []
        for a in assets:
            eids.extend(a.evidence_ids)

        has_critical = any(a.criticality == AssetCriticality.CRITICAL for a in assets)
        has_high = any(a.criticality == AssetCriticality.HIGH for a in assets)
        has_medium = any(a.criticality == AssetCriticality.MEDIUM for a in assets)

        if has_critical:
            return (
                9.5,
                f"Critical infrastructure asset(s) compromised (e.g. Domain Controller, Core Database).",
                eids
            )
        elif has_high:
            return (
                7.5,
                f"High-priority server(s) or administrative accounts compromised.",
                eids
            )
        elif has_medium:
            return (
                5.0,
                f"Standard corporate endpoint(s) or workstations compromised.",
                eids
            )
        return (3.0, "Low-criticality or isolated endpoint(s) impacted.", eids)

    @classmethod
    def _compute_data_impact_factor(
        cls,
        agent3: Dict[str, Any],
        agent4: Dict[str, Any],
        findings: List[Any]
    ) -> (float, str, List[str]):
        eids: List[str] = []
        has_exfiltration = False
        has_cred_dump = False
        has_discovery = False

        for f in findings:
            fact = str(getattr(f, "fact", "") if hasattr(f, "fact") else f.get("fact", "")).lower()
            fid = getattr(f, "finding_id", "") if hasattr(f, "finding_id") else f.get("finding_id", "")
            if any(term in fact for term in ["exfiltrat", "data leak", "data transfer"]):
                has_exfiltration = True
                if fid: eids.append(str(fid))
            if any(term in fact for term in ["lsass", "sam dump", "mimikatz", "dumped credential"]):
                has_cred_dump = True
                if fid: eids.append(str(fid))
            if any(term in fact for term in ["whoami", "ipconfig", "net user", "systeminfo", "directory list"]):
                has_discovery = True
                if fid: eids.append(str(fid))

        if has_exfiltration:
            return (9.0, "Confirmed outbound data exfiltration or sensitive information disclosure.", eids)
        elif has_cred_dump:
            return (8.0, "Credential harvesting / LSASS memory access substantiated.", eids)
        elif has_discovery:
            return (4.0, "Internal reconnaissance and environment discovery observed without bulk exfiltration.", eids)
        return (1.0, "No sensitive data access, credential theft, or exfiltration detected.", [])

    @classmethod
    def _compute_system_integrity_factor(
        cls,
        agent4: Dict[str, Any],
        findings: List[Any]
    ) -> (float, str, List[str]):
        eids: List[str] = []
        has_ransomware = False
        has_persistence = False
        has_execution = False

        for f in findings:
            fact = str(getattr(f, "fact", "") if hasattr(f, "fact") else f.get("fact", "")).lower()
            fid = getattr(f, "finding_id", "") if hasattr(f, "finding_id") else f.get("finding_id", "")
            if any(term in fact for term in ["ransomware", "encrypt files", "wiper"]):
                has_ransomware = True
                if fid: eids.append(str(fid))
            if any(term in fact for term in ["scheduled task", "registry autorun", "service install", "persistence"]):
                has_persistence = True
                if fid: eids.append(str(fid))
            if any(term in fact for term in ["powershell", "cmd.exe", "executed", "binary spawn"]):
                has_execution = True
                if fid: eids.append(str(fid))

        # Check Agent 4 claims
        for claim in agent4.get("claims", []):
            stage = str(claim.get("infection_stage", "")).lower()
            cited = claim.get("cited_evidence_ids", []) or []
            if "persistence" in stage:
                has_persistence = True
                eids.extend(cited)
            if "execution" in stage:
                has_execution = True
                eids.extend(cited)

        if has_ransomware:
            return (10.0, "Severe destructive integrity damage (ransomware/wiping detected).", eids)
        elif has_persistence:
            return (7.5, "Persistent malware execution mechanism established (scheduled task/registry).", eids)
        elif has_execution:
            return (5.0, "Unauthorized code execution observed without established persistence.", eids)
        return (1.0, "No unauthorized modification or persistent system tampering detected.", [])

    @classmethod
    def _compute_availability_factor(
        cls,
        findings: List[Any]
    ) -> (float, str, List[str]):
        eids: List[str] = []
        has_dos = False
        has_crashes = False

        for f in findings:
            fact = str(getattr(f, "fact", "") if hasattr(f, "fact") else f.get("fact", "")).lower()
            fid = getattr(f, "finding_id", "") if hasattr(f, "finding_id") else f.get("finding_id", "")
            if any(term in fact for term in ["denial of service", "server down", "reboot loop", "unbootable"]):
                has_dos = True
                if fid: eids.append(str(fid))
            if any(term in fact for term in ["process killed", "service crash", "terminated"]):
                has_crashes = True
                if fid: eids.append(str(fid))

        if has_dos:
            return (9.0, "Service disruption or critical host outage verified.", eids)
        elif has_crashes:
            return (4.0, "Isolated process terminations or transient service degradation noted.", eids)
        return (1.0, "Standard system availability preserved; no service interruption observed.", [])

    @classmethod
    def _compute_scope_factor(
        cls,
        agent3: Dict[str, Any],
        assets: List[AffectedAsset]
    ) -> (float, str, List[str]):
        lat_movement = agent3.get("lateral_movement", [])
        eids: List[str] = []

        if lat_movement and len(lat_movement) > 1:
            for lm in lat_movement:
                eids.extend(lm.get("evidence_ids", []))
            return (8.5, f"Multi-host enterprise lateral movement confirmed ({len(lat_movement)} pivots).", eids)
        elif lat_movement and len(lat_movement) == 1:
            for lm in lat_movement:
                eids.extend(lm.get("evidence_ids", []))
            return (6.0, "Lateral movement confirmed to a secondary system.", eids)
        elif len(assets) > 1:
            return (4.0, f"Multiple entities impacted within local subnet ({len(assets)} assets).", [])
        return (2.0, "Compromise strictly confined to a single initial host.", [])

    @classmethod
    def _compute_technical_vulnerability_factor(
        cls,
        cvss: Optional[CVSSAssessment]
    ) -> (float, str, List[str]):
        if cvss and cvss.base_score is not None:
            return (
                float(cvss.base_score),
                f"Directly derived from deterministic CVSS v3.1 base score ({cvss.base_score}/10.0).",
                cvss.evidence_ids
            )
        elif cvss and cvss.score_range_max is not None and cvss.score_range_min is not None:
            mid = round((cvss.score_range_min + cvss.score_range_max) / 2.0, 1)
            return (
                mid,
                f"Bounded by confirmed CVSS partial metrics: [{cvss.score_range_min} - {cvss.score_range_max}].",
                cvss.evidence_ids
            )
        return (5.0, "Baseline technical vulnerability severity estimated in absence of full CVSS vector.", [])

    @classmethod
    def _identify_top_drivers(cls, factors: Dict[str, ISSFactorScore]) -> str:
        sorted_factors = sorted(factors.values(), key=lambda f: f.weighted_score, reverse=True)
        top = [f"{f.factor_name} ({f.weighted_score} pts)" for f in sorted_factors[:2]]
        return " & ".join(top)
