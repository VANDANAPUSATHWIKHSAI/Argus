"""
Forensic Analysis Layer — Batch Orchestrator
===========================================
Dispatches Forensic Correlation Records (FCRs) to registered analysis engines,
persists Findings to the UnifiedEvidenceStore, adapts Findings to FIRFindings,
and inserts them into the FIRRepository.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional

from forensic_analysis.schemas import Finding, finding_to_fir
from forensic_analysis.router import route_fcr
from forensic_analysis.unified_store import UnifiedEvidenceStore
from forensic_analysis.network_analysis.network_engine import NetworkAnalysisEngine
from forensic_analysis.log_analysis.log_engine import LogAnalysisEngine
from forensic_analysis.endpoint_analysis.endpoint_engine import EndpointAnalysisEngine
from forensic_analysis.memory_analysis.memory_engine import MemoryAnalysisEngine
from forensic_analysis.email_analysis.email_engine import EmailAnalysisEngine

from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.schemas import Artifact
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway

logger = logging.getLogger(__name__)

# ENGINE REGISTRY: Active deterministic forensic analysis engines ('network', 'log', 'endpoint', 'memory', 'email')
ENGINE_REGISTRY: Dict[str, Any] = {
    "network": NetworkAnalysisEngine(),
    "log": LogAnalysisEngine(),
    "endpoint": EndpointAnalysisEngine(),
    "memory": MemoryAnalysisEngine(),
    "email": EmailAnalysisEngine(),
}

# Module-level default unified store singleton
unified_store = UnifiedEvidenceStore()


def process_fcr_batch(
    case_id: str,
    fcr_objects: List[CorrelationRecord],
    artifacts_by_id: Dict[str, Artifact],
    fir_repo: FIRRepository,
    store: Optional[UnifiedEvidenceStore] = None,
    tenant_id: str = "default"
) -> List[Finding]:
    """
    Processes a batch of FCR objects for a given case:
    1. Routes each FCR to target engines via route_fcr().
    2. Dispatches to registered engines in ENGINE_REGISTRY (logs warning & skips unregistered engines).
    3. Collects Findings, writes each to UnifiedEvidenceStore.
    4. Converts Findings to FIRFindings via finding_to_fir() and inserts into FIRRepository.
    """
    if not case_id or not case_id.strip():
        raise ValueError("case_id is required for process_fcr_batch.")

    target_store = store or unified_store
    all_findings: List[Finding] = []

    for fcr in fcr_objects:
        engine_names = route_fcr(fcr, artifacts_by_id)

        for engine_name in engine_names:
            engine = ENGINE_REGISTRY.get(engine_name)

            if engine is None:
                logger.warning(
                    "Orchestrator: Unregistered analysis engine '%s' requested for FCR '%s'. Skipping engine execution.",
                    engine_name, getattr(fcr, "correlation_id", "UNKNOWN")
                )
                continue

            try:
                findings = engine.analyze([fcr], artifacts_by_id)
                for finding in findings:
                    if tenant_id and tenant_id != "default":
                        finding.tenant_id = tenant_id
                    all_findings.append(finding)
                    # Write to Unified Evidence Store
                    target_store.write_finding(finding)

                    # Adapt & Insert into FIR Repository with SanitizationGateway
                    if fir_repo is not None:
                        sanitizer = SanitizationGateway()
                        ctx = sanitizer.sanitize_finding(finding)
                        fir_finding = finding_to_fir(finding)
                        fir_finding.sanitized_fact = ctx.sanitized_fact
                        fir_finding.injection_flagged = ctx.injection_flagged
                        fir_finding.injection_score = ctx.injection_score
                        fir_repo.insert(fir_finding)

            except Exception as e:
                logger.error(
                    "Orchestrator: Exception raised while executing engine '%s' for FCR '%s': %s",
                    engine_name, getattr(fcr, "correlation_id", "UNKNOWN"), e, exc_info=True
                )

    return all_findings
