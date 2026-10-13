"""
Affected Assets & Inventory Extraction Engine
==============================================
Discovers, classifies, and assesses risk for assets, systems, and accounts
impacted across the digital forensic investigation.
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Any, Optional, Set
from agents.agent6_impact_assessment.schemas import (
    AffectedAsset,
    AssetType,
    AssetCriticality,
    CompromiseState
)

logger = logging.getLogger(__name__)


class AssetExtractor:
    """
    Deterministic asset and identity impact extraction engine.
    Extracts affected hosts, domain controllers, databases, and user accounts
    from Agent 3, Agent 4, and FIR findings with evidence traceability.
    """

    RE_HOSTNAME = re.compile(r"\b(?:WIN-[A-Z0-9_\-]+|DESKTOP-[A-Z0-9_\-]+|CORP-[A-Z0-9_\-]+|DC-[0-9]{1,3}|SRV-[A-Z0-9_\-]+|[a-zA-Z0-9_\-]+\.corp|[a-zA-Z0-9_\-]+\.internal)\b", re.I)
    RE_USER = re.compile(r"\b(?:user|account)\s*['\"]?([a-zA-Z0-9_\.\-]+)['\"]?", re.I)
    RE_IP = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    @classmethod
    def extract_assets(
        cls,
        agent3_output: Optional[Dict[str, Any]] = None,
        agent4_output: Optional[Dict[str, Any]] = None,
        fir_findings: Optional[List[Any]] = None
    ) -> List[AffectedAsset]:
        agent3_output = agent3_output or {}
        agent4_output = agent4_output or {}
        fir_findings = fir_findings or []

        assets_by_id: Dict[str, AffectedAsset] = {}

        # 1. Extract from Agent 4 IOCs and Claims
        for claim in agent4_output.get("claims", []):
            findings_summary = claim.get("findings_summary", "")
            cited = claim.get("cited_evidence_ids", []) or []
            stage = claim.get("infection_stage", "")

            # Look for hostnames
            hosts = cls.RE_HOSTNAME.findall(findings_summary)
            for h in hosts:
                cls._upsert_asset(
                    assets_by_id,
                    asset_id=h.upper(),
                    asset_type=cls._classify_host_type(h),
                    criticality=cls._classify_host_criticality(h),
                    compromise_state=CompromiseState.CONFIRMED_COMPROMISED,
                    risk_score=8.5 if "persistence" in str(stage).lower() else 7.0,
                    impact_details=f"Target of {stage} execution: '{findings_summary[:100]}'",
                    evidence_ids=cited
                )

            # Look for user accounts
            user_matches = cls.RE_USER.findall(findings_summary)
            for m in user_matches:
                username = (m if isinstance(m, str) else next((u for u in m if u), "")).strip("'\"")
                if username and username.lower() not in {"admin", "system"}:
                    cls._upsert_asset(
                        assets_by_id,
                        asset_id=username.lower(),
                        asset_type=AssetType.USER_ACCOUNT,
                        criticality=AssetCriticality.MEDIUM,
                        compromise_state=CompromiseState.CONFIRMED_COMPROMISED,
                        risk_score=6.5,
                        impact_details=f"User account context compromised during execution: {findings_summary[:80]}",
                        evidence_ids=cited
                    )
                elif username and username.lower() in {"admin", "system"}:
                    cls._upsert_asset(
                        assets_by_id,
                        asset_id=username.lower(),
                        asset_type=AssetType.USER_ACCOUNT,
                        criticality=AssetCriticality.HIGH,
                        compromise_state=CompromiseState.CONFIRMED_COMPROMISED,
                        risk_score=9.0,
                        impact_details=f"Privileged account authority utilized: {findings_summary[:80]}",
                        evidence_ids=cited
                    )

            # Look for internal IPs
            ioc_col = claim.get("ioc_collection", {}) or {}
            for ip in ioc_col.get("ip_addresses", []):
                if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
                    cls._upsert_asset(
                        assets_by_id,
                        asset_id=ip,
                        asset_type=AssetType.ENDPOINT,
                        criticality=AssetCriticality.MEDIUM,
                        compromise_state=CompromiseState.CONFIRMED_COMPROMISED,
                        risk_score=7.0,
                        impact_details=f"Internal IP endpoint observed in C2/socket communications.",
                        evidence_ids=cited
                    )

        # 2. Extract from Agent 3 Lateral Movement & Infection Path
        for lm in agent3_output.get("lateral_movement", []):
            src = lm.get("source_host")
            dst = lm.get("destination_host")
            eids = lm.get("evidence_ids", [])
            if src:
                cls._upsert_asset(
                    assets_by_id,
                    asset_id=src.upper(),
                    asset_type=cls._classify_host_type(src),
                    criticality=cls._classify_host_criticality(src),
                    compromise_state=CompromiseState.CONFIRMED_COMPROMISED,
                    risk_score=8.5,
                    impact_details=f"Source pivot host for lateral movement.",
                    evidence_ids=eids
                )
            if dst:
                cls._upsert_asset(
                    assets_by_id,
                    asset_id=dst.upper(),
                    asset_type=cls._classify_host_type(dst),
                    criticality=cls._classify_host_criticality(dst),
                    compromise_state=CompromiseState.TARGETED,
                    risk_score=8.0,
                    impact_details=f"Target host targeted via lateral movement.",
                    evidence_ids=eids
                )

        # 3. Extract from FIR findings
        for f in fir_findings:
            fact = str(getattr(f, "fact", "") if hasattr(f, "fact") else f.get("fact", ""))
            fid = getattr(f, "finding_id", "") if hasattr(f, "finding_id") else f.get("finding_id", "")
            fids = [str(fid)] if fid else []

            hosts = cls.RE_HOSTNAME.findall(fact)
            for h in hosts:
                cls._upsert_asset(
                    assets_by_id,
                    asset_id=h.upper(),
                    asset_type=cls._classify_host_type(h),
                    criticality=cls._classify_host_criticality(h),
                    compromise_state=CompromiseState.SUSPECTED_COMPROMISED,
                    risk_score=6.0,
                    impact_details=f"Identified in finding: {fact[:90]}",
                    evidence_ids=fids
                )

        # Fallback if no assets discovered
        if not assets_by_id:
            assets_by_id["PRIMARY-HOST-01"] = AffectedAsset(
                asset_id="PRIMARY-HOST-01",
                asset_type=AssetType.ENDPOINT,
                criticality=AssetCriticality.MEDIUM,
                compromise_state=CompromiseState.CONFIRMED_COMPROMISED,
                risk_score=6.0,
                impact_details="Primary evidentiary endpoint analyzed in investigation.",
                evidence_ids=[]
            )

        return list(assets_by_id.values())

    @classmethod
    def _upsert_asset(
        cls,
        assets: Dict[str, AffectedAsset],
        asset_id: str,
        asset_type: AssetType,
        criticality: AssetCriticality,
        compromise_state: CompromiseState,
        risk_score: float,
        impact_details: str,
        evidence_ids: List[str]
    ):
        if asset_id in assets:
            existing = assets[asset_id]
            # Merge evidence IDs
            merged_eids = sorted(list(set(existing.evidence_ids + evidence_ids)))
            # Highest risk score
            new_risk = max(existing.risk_score, risk_score)
            existing.evidence_ids = merged_eids
            existing.risk_score = new_risk
            if existing.compromise_state != CompromiseState.CONFIRMED_COMPROMISED and compromise_state == CompromiseState.CONFIRMED_COMPROMISED:
                existing.compromise_state = CompromiseState.CONFIRMED_COMPROMISED
        else:
            assets[asset_id] = AffectedAsset(
                asset_id=asset_id,
                asset_type=asset_type,
                criticality=criticality,
                compromise_state=compromise_state,
                risk_score=risk_score,
                impact_details=impact_details,
                evidence_ids=evidence_ids
            )

    @classmethod
    def _classify_host_type(cls, host_str: str) -> AssetType:
        h = host_str.upper()
        if "DC" in h or "DOMAIN" in h:
            return AssetType.DOMAIN_CONTROLLER
        elif "SRV" in h or "SERVER" in h or "SQL" in h or "DB" in h:
            return AssetType.SERVER
        return AssetType.ENDPOINT

    @classmethod
    def _classify_host_criticality(cls, host_str: str) -> AssetCriticality:
        h = host_str.upper()
        if "DC" in h or "DOMAIN" in h or "PROD-DB" in h:
            return AssetCriticality.CRITICAL
        elif "SRV" in h or "SERVER" in h:
            return AssetCriticality.HIGH
        return AssetCriticality.MEDIUM
