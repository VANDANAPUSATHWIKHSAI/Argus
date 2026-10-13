"""
Recovery Recommendations & Checklist Engine
=============================================
Generates prioritized, actionable incident recovery operations and a structured
checklist for digital forensics and incident response (DFIR) teams.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Any, Optional, Set
from agents.agent6_impact_assessment.schemas import (
    RecoveryAction,
    RecoveryChecklist,
    RecoveryPhase,
    RecoveryPriority,
    ResponsibleRole,
    AffectedAsset,
    ISSAssessment,
    CVSSAssessment
)

logger = logging.getLogger(__name__)


class RecoveryEngine:
    """
    Deterministic recovery recommendation and checklist generator.
    Translates observed forensic threats into concrete operational playbooks.
    """

    @classmethod
    def generate_recovery_plan(
        cls,
        affected_assets: List[AffectedAsset],
        iss_assessment: ISSAssessment,
        cvss_assessment: Optional[CVSSAssessment] = None,
        agent3_output: Optional[Dict[str, Any]] = None,
        agent4_output: Optional[Dict[str, Any]] = None
    ) -> (List[RecoveryAction], RecoveryChecklist):
        agent3_output = agent3_output or {}
        agent4_output = agent4_output or {}

        actions: List[RecoveryAction] = []
        action_counter = 1

        # Collect target host IDs
        host_ids = [a.asset_id for a in affected_assets if a.asset_type.value in {"ENDPOINT", "SERVER", "DOMAIN_CONTROLLER"}]
        account_ids = [a.asset_id for a in affected_assets if a.asset_type.value == "USER_ACCOUNT"]

        # Collect C2 IPs and file hashes
        c2_ips: Set[str] = set()
        hashes_to_purge: Set[str] = set()
        persistence_tasks: Set[str] = set()
        all_eids: Set[str] = set()

        for claim in agent4_output.get("claims", []):
            ioc_col = claim.get("ioc_collection", {}) or {}
            c2_ips.update(ioc_col.get("ip_addresses", []))
            hashes_to_purge.update(ioc_col.get("hashes", []))
            cited = claim.get("cited_evidence_ids", []) or []
            all_eids.update(cited)

            summary = str(claim.get("findings_summary", "")).lower()
            if "scheduled task" in summary or "persistence" in summary:
                persistence_tasks.add("update.exe")

        eids_list = sorted(list(all_eids))

        # ── 1. Phase 1: Containment (P1_IMMEDIATE) ───────────────────────────
        if host_ids:
            actions.append(RecoveryAction(
                action_id=f"REC-{action_counter:03d}",
                phase=RecoveryPhase.CONTAINMENT,
                priority=RecoveryPriority.P1_IMMEDIATE,
                title=f"Isolate Compromised Host(s) from Production Network",
                description=(
                    f"Perform network-level quarantine for host(s): {', '.join(host_ids)}. "
                    f"Maintain only EDR sensor connection to prevent lateral pivot while preserving volatile evidence."
                ),
                target_assets=host_ids,
                responsible_role=ResponsibleRole.SOC_L2,
                verification_step="Confirm host ping is dropped and only management EDR traffic is permitted.",
                evidence_ids=eids_list
            ))
            action_counter += 1

        if c2_ips:
            actions.append(RecoveryAction(
                action_id=f"REC-{action_counter:03d}",
                phase=RecoveryPhase.CONTAINMENT,
                priority=RecoveryPriority.P1_IMMEDIATE,
                title=f"Enforce Perimeter Firewall Blocks for Observed C2 Indicators",
                description=(
                    f"Immediately block all outbound and inbound traffic to command-and-control IP(s): {', '.join(c2_ips)} "
                    f"across enterprise perimeter firewalls, egress proxies, and DNS resolvers."
                ),
                target_assets=list(c2_ips),
                responsible_role=ResponsibleRole.NETWORK_ADMIN,
                verification_step="Verify firewall drop rule counters increment on synthetic test beacon.",
                evidence_ids=eids_list
            ))
            action_counter += 1

        if account_ids:
            actions.append(RecoveryAction(
                action_id=f"REC-{action_counter:03d}",
                phase=RecoveryPhase.CONTAINMENT,
                priority=RecoveryPriority.P1_IMMEDIATE,
                title=f"Revoke Active Sessions and Reset Credentials for Compromised Accounts",
                description=(
                    f"Terminate active Kerberos tickets, refresh tokens, and force password change for identity/account(s): {', '.join(account_ids)}."
                ),
                target_assets=account_ids,
                responsible_role=ResponsibleRole.IAM_ADMIN,
                verification_step="Query Active Directory / IdP to ensure password last set timestamp is updated and active tokens revoked.",
                evidence_ids=eids_list
            ))
            action_counter += 1

        # ── 2. Phase 2: Eradication (P2_HIGH) ─────────────────────────────────
        if persistence_tasks or hashes_to_purge:
            target_str = ", ".join(list(hashes_to_purge)[:3]) if hashes_to_purge else "scheduled task artifacts"
            actions.append(RecoveryAction(
                action_id=f"REC-{action_counter:03d}",
                phase=RecoveryPhase.ERADICATION,
                priority=RecoveryPriority.P2_HIGH,
                title="Eradicate Malicious Persistence Mechanisms and Payloads",
                description=(
                    f"Delete unauthorized scheduled tasks (e.g., 'update.exe'), purge registry Run keys, "
                    f"and delete malicious payloads matching hashes: {target_str}."
                ),
                target_assets=host_ids or ["AFFECTED_HOSTS"],
                responsible_role=ResponsibleRole.SYSADMIN,
                verification_step="Execute Schtasks query and filesystem hash check to verify binary and task removal.",
                evidence_ids=eids_list
            ))
            action_counter += 1

        actions.append(RecoveryAction(
            action_id=f"REC-{action_counter:03d}",
            phase=RecoveryPhase.ERADICATION,
            priority=RecoveryPriority.P2_HIGH,
            title="Scan File System with Custom YARA Rules for Residual Droppers",
            description="Run full-disk forensic YARA scan across all affected endpoints to ensure no secondary droppers remain.",
            target_assets=host_ids or ["AFFECTED_HOSTS"],
            responsible_role=ResponsibleRole.FORENSIC_ANALYST,
            verification_step="Verify YARA scan report returns zero undetected matches across disk volumes.",
            evidence_ids=eids_list
        ))
        action_counter += 1

        # ── 3. Phase 3: Recovery (P3_MEDIUM) ──────────────────────────────────
        actions.append(RecoveryAction(
            action_id=f"REC-{action_counter:03d}",
            phase=RecoveryPhase.RECOVERY,
            priority=RecoveryPriority.P3_MEDIUM,
            title="Rebuild or Restore Endpoints from Verified Clean Golden Images",
            description=(
                "Re-image impacted endpoints from clean baseline templates or restore data from offline backups "
                "prior to confirmed compromise timestamp."
            ),
            target_assets=host_ids or ["AFFECTED_HOSTS"],
            responsible_role=ResponsibleRole.SYSADMIN,
            verification_step="Confirm golden image integrity checksum and ensure latest OS security updates applied.",
            evidence_ids=eids_list
        ))
        action_counter += 1

        actions.append(RecoveryAction(
            action_id=f"REC-{action_counter:03d}",
            phase=RecoveryPhase.RECOVERY,
            priority=RecoveryPriority.P3_MEDIUM,
            title="Gradual Network Re-Integration under Elevated Telemetry Monitoring",
            description="Re-attach restored systems to their production subnets with real-time EDR debug-level auditing enabled for 72 hours.",
            target_assets=host_ids or ["AFFECTED_HOSTS"],
            responsible_role=ResponsibleRole.SOC_L2,
            verification_step="Audit telemetry stream to ensure zero anomalous network beacons or unauthorized process spawns.",
            evidence_ids=eids_list
        ))
        action_counter += 1

        # ── 4. Phase 4: Hardening (P4_LOW) ────────────────────────────────────
        actions.append(RecoveryAction(
            action_id=f"REC-{action_counter:03d}",
            phase=RecoveryPhase.HARDENING,
            priority=RecoveryPriority.P4_LOW,
            title="Implement Attack Surface Reduction & PowerShell Constrained Language Mode",
            description=(
                "Enforce PowerShell ConstrainedLanguage mode via AppLocker/WDAC and disable WScript/CScript execution "
                "for standard domain users."
            ),
            target_assets=["ENTERPRISE_GPO"],
            responsible_role=ResponsibleRole.SYSADMIN,
            verification_step="Verify Group Policy Object (GPO) propagation and test PowerShell execution policy restriction.",
            evidence_ids=[]
        ))
        action_counter += 1

        actions.append(RecoveryAction(
            action_id=f"REC-{action_counter:03d}",
            phase=RecoveryPhase.HARDENING,
            priority=RecoveryPriority.P4_LOW,
            title="Update SIEM Correlation Rules for Observed TTPs",
            description=(
                "Deploy detection rules targeting cmd.exe -> powershell.exe parent-child anomalies and "
                "unusual outbound socket connections on non-standard ports."
            ),
            target_assets=["SIEM_DETECTION_ENGINE"],
            responsible_role=ResponsibleRole.SOC_L2,
            verification_step="Trigger detection rule unit test and confirm alert dispatch to SOC queue.",
            evidence_ids=[]
        ))

        # Build structured checklist
        checklist = RecoveryChecklist(
            containment_steps=[a for a in actions if a.phase == RecoveryPhase.CONTAINMENT],
            eradication_steps=[a for a in actions if a.phase == RecoveryPhase.ERADICATION],
            recovery_steps=[a for a in actions if a.phase == RecoveryPhase.RECOVERY],
            hardening_steps=[a for a in actions if a.phase == RecoveryPhase.HARDENING],
            total_actions=len(actions)
        )

        return actions, checklist
