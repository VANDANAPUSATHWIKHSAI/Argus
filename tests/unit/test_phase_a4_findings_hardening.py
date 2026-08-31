"""
Unit Test Suite for ARGUS Phase A.4 Finding Layer, Deduplication, Provenance, and Analyst Service
===================================================================================================
Validates:
1. Finding.finding_fingerprint property (deterministic, stable, tenant/case/layer/fact/sources seed)
2. FIRFinding top-level provenance linkage (source_artifact_id and finding_fingerprint)
3. UnifiedEvidenceStore semantic fingerprint deduplication
4. FIRRepository fingerprint deduplication & review gate transitions
5. UnifiedTimelineBuilder Finding ingestion (event_type="finding" with finding.timestamp)
6. AnalystFindingService query, review workflow, and export gating
7. Case and tenant isolation boundaries
8. AST security invariants across forensic_analysis, fir, and sanitization
"""

import unittest
import ast
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

from forensic_analysis.schemas import Finding, finding_to_fir
from fir.schemas import FIRFinding, ReviewStatus, UnreviewedFindingError
from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from forensic_analysis.unified_store import UnifiedEvidenceStore
from preprocessing.fcr_engine.timeline import UnifiedTimelineBuilder
from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.schemas import CorrelationRecord


class TestPhaseA4FindingsHardening(unittest.TestCase):
    """Exhaustive test suite for Phase A.4 Finding Layer Hardening."""

    def setUp(self):
        self.case_id = "CASE-PHASE-A4-TEST"
        self.tenant_id = "tenant-a4"
        self.fir_repo = FIRRepository()
        self.unified_store = UnifiedEvidenceStore()
        self.timeline_builder = UnifiedTimelineBuilder()
        self.service = AnalystFindingService(
            fir_repo=self.fir_repo,
            unified_store=self.unified_store,
            timeline_builder=self.timeline_builder
        )

    # ─────────────────────────────────────────────────────────────────
    # 1. FINDING FINGERPRINT & IDENTITY TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_finding_fingerprint_determinism_and_stability(self):
        """Verify finding_fingerprint is deterministic and excludes timestamps, finding_ids, or random values."""
        t1 = datetime(2026, 8, 31, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 8, 31, 11, 30, 0, tzinfo=timezone.utc)

        f1 = Finding(
            finding_id="uuid-1111",
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="Suspicious process cmd.exe spawned by winword.exe",
            confidence=0.90,
            severity="high",
            mitre_mapping="T1059.003",
            timestamp=t1,
            evidence_reference="CORR-100",
            source_artifact_id="art-555",
            layer="endpoint",
            contributing_correlation_ids=["CORR-100"]
        )

        f2 = Finding(
            finding_id="uuid-2222", # Different finding_id UUID
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="Suspicious process cmd.exe spawned by winword.exe", # Same fact
            confidence=0.90,
            severity="high",
            mitre_mapping="T1059.003",
            timestamp=t2, # Different timestamp
            evidence_reference="CORR-100",
            source_artifact_id="art-555",
            layer="endpoint",
            contributing_correlation_ids=["CORR-100"]
        )

        self.assertEqual(f1.finding_fingerprint, f2.finding_fingerprint)
        self.assertTrue(f1.finding_fingerprint.startswith("FFP-"))

    # ─────────────────────────────────────────────────────────────────
    # 2. TOP-LEVEL PROVENANCE & FIR LINKAGE TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_fir_finding_top_level_provenance_linkage(self):
        """Verify finding_to_fir populates source_artifact_id and finding_fingerprint on FIRFinding."""
        f = Finding(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="Malicious DLL injection detected in lsass.exe",
            confidence=0.95,
            severity="critical",
            evidence_reference="CORR-200",
            source_artifact_id="art-777",
            layer="memory",
            contributing_correlation_ids=["CORR-200"]
        )

        fir_f = finding_to_fir(f)
        self.assertEqual(fir_f.source_artifact_id, "art-777")
        self.assertEqual(fir_f.finding_fingerprint, f.finding_fingerprint)
        self.assertEqual(fir_f.layer, "memory")

    # ─────────────────────────────────────────────────────────────────
    # 3. UNIFIED STORE & FIR REPOSITORY FINGERPRINT DEDUPLICATION
    # ─────────────────────────────────────────────────────────────────

    def test_unified_store_and_fir_repository_fingerprint_deduplication(self):
        """Verify write_finding and FIRRepository.insert deduplicate repeat findings based on fingerprint."""
        f1 = Finding(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="Unauthorized SSH login attempt from 192.0.2.45",
            confidence=0.85,
            severity="medium",
            evidence_reference="CORR-300",
            source_artifact_id="art-888",
            layer="log"
        )
        f2 = Finding(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="Unauthorized SSH login attempt from 192.0.2.45",
            confidence=0.85,
            severity="medium",
            evidence_reference="CORR-300",
            source_artifact_id="art-888",
            layer="log"
        )

        self.unified_store.write_finding(f1)
        self.unified_store.write_finding(f2)

        read_back = self.unified_store.read_findings(self.case_id, tenant_id=self.tenant_id)
        self.assertEqual(len(read_back), 1)

        fir1 = finding_to_fir(f1)
        fir2 = finding_to_fir(f2)
        self.fir_repo.insert(fir1)
        self.fir_repo.insert(fir2)

        self.assertEqual(len(self.fir_repo.findings), 1)

    # ─────────────────────────────────────────────────────────────────
    # 4. TIMELINE FINDING INGESTION TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_timeline_finding_ingestion_with_occurrence_timestamp(self):
        """Verify UnifiedTimelineBuilder ingests Finding objects as event_type='finding' using finding.timestamp."""
        t_event = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
        art = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", timestamp=t_event - timedelta(minutes=10), host_id="HOST-A")
        
        f = Finding(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="Persistence via registry Run key",
            confidence=0.90,
            severity="high",
            timestamp=t_event,
            evidence_reference="CORR-400",
            source_artifact_id="art-999",
            layer="endpoint"
        )

        timeline = self.timeline_builder.build_timeline(artifacts=[art], findings=[f])
        self.assertEqual(len(timeline), 2)
        finding_events = [e for e in timeline if e.event_type == "finding"]
        self.assertEqual(len(finding_events), 1)
        self.assertEqual(finding_events[0].timestamp, t_event)
        self.assertIn("[HIGH]", finding_events[0].summary)

    # ─────────────────────────────────────────────────────────────────
    # 5. ANALYST FINDING SERVICE & REVIEW LIFECYCLE TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_analyst_finding_service_review_and_export_gating(self):
        """Verify review status transitions and export gating (pending_review blocks export unless allowed)."""
        f = Finding(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact="Phishing link clicked in Outlook",
            confidence=0.88,
            severity="high",
            evidence_reference="CORR-500",
            source_artifact_id="art-100",
            layer="email"
        )
        fir_f = finding_to_fir(f)
        self.fir_repo.insert(fir_f)

        # Unreviewed export attempt (default allow_unreviewed=False) -> empty list
        exported_default = self.service.export_report(self.case_id, tenant_id=self.tenant_id, allow_unreviewed=False)
        self.assertEqual(len(exported_default), 0)

        # Mark confirmed
        self.service.mark_review(fir_f.finding_id, case_id=self.case_id, status=ReviewStatus.ANALYST_CONFIRMED, reviewed_by="analyst_alice", tenant_id=self.tenant_id)

        # Export confirmed findings
        exported_confirmed = self.service.export_report(self.case_id, tenant_id=self.tenant_id, allow_unreviewed=False)
        self.assertEqual(len(exported_confirmed), 1)
        self.assertEqual(exported_confirmed[0]["_review_gate"]["review_status"], "analyst_confirmed")

    # ─────────────────────────────────────────────────────────────────
    # 6. CASE & TENANT ISOLATION TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_strict_case_and_tenant_isolation(self):
        """Verify findings from CASE-A/tenant-1 cannot be accessed from CASE-B/tenant-2."""
        f_a = Finding(case_id="CASE-A", tenant_id="tenant-1", fact="Fact A", confidence=0.8, severity="low", evidence_reference="CORR-1", source_artifact_id="art-1", layer="endpoint")
        f_b = Finding(case_id="CASE-B", tenant_id="tenant-2", fact="Fact B", confidence=0.8, severity="low", evidence_reference="CORR-2", source_artifact_id="art-2", layer="endpoint")

        self.service.fir_repo.insert(finding_to_fir(f_a))
        self.service.fir_repo.insert(finding_to_fir(f_b))

        findings_a = self.service.list_findings("CASE-A", tenant_id="tenant-1")
        self.assertEqual(len(findings_a), 1)
        self.assertEqual(findings_a[0].fact, "Fact A")

        findings_b_leak = self.service.list_findings("CASE-A", tenant_id="tenant-2")
        self.assertEqual(len(findings_b_leak), 0)

    # ─────────────────────────────────────────────────────────────────
    # 7. AST SECURITY INVARIANTS
    # ─────────────────────────────────────────────────────────────────

    def test_ast_security_invariants(self):
        """Verify 0 eval, exec, shell=True, os.system, or pickle.loads across forensic_analysis, fir, and sanitization."""
        target_dirs = [Path("forensic_analysis"), Path("fir"), Path("sanitization")]
        violations = []

        for td in target_dirs:
            for p in td.rglob("*.py"):
                try:
                    tree = ast.parse(p.read_text(encoding="utf-8", errors="ignore"), filename=str(p))
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                                violations.append(f"{p}: call to {node.func.id}")
                            elif isinstance(node.func, ast.Attribute):
                                if node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                                    violations.append(f"{p}: os.system call")
                                elif node.func.attr == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                                    violations.append(f"{p}: pickle.loads call")

                            for kw in node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    violations.append(f"{p}: shell=True argument")
                except SyntaxError:
                    pass

        self.assertEqual(len(violations), 0, f"AST Security Violations: {violations}")


if __name__ == "__main__":
    unittest.main()
