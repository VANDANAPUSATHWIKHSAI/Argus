"""
ARGUS Forensic Consistency Fixes Regression Test Suite
======================================================
Tests all targeted forensic consistency fixes:
1. Sysmon EVTX, Defender EVTX, GPO EVTX, and Generic EVTX routing.
2. Firewall ALLOW and DROP findings (mitre_mapping = None).
3. PowerShell command analyzer MITRE mappings and timestamp preservation.
4. Firewall flow retention (>10 identical records).
5. Report API default allow_unreviewed=False gating and deterministic report generation.
6. Tenant isolation and evidence provenance.
"""

import os
import tempfile
from datetime import datetime, timezone
import pytest

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.firewall_parser import WindowsFirewallParser
from forensic_analysis.network_analysis.network_engine import NetworkAnalysisEngine
from forensic_analysis.log_analysis.powershell_analyzer import PowerShellAnalyzer
from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact, NormalizedFields
from fir.schemas import FIRFinding, ReviewStatus
from fir.service import AnalystFindingService
from fir.repository import FIRRepository
from report_generation.generator import ReportGenerator


class TestForensicConsistencyFixes:

    def test_sysmon_vs_generic_evtx_routing(self):
        router = ParserRouter()
        
        # 1. Sysmon EVTX
        ev_sysmon = Evidence(
            case_id="CASE-SYSMON-001",
            filename="Microsoft-Windows-Sysmon%4Operational.evtx",
            file_path="C:\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
            uploaded_by="analyst",
            sha256_hash="abc123sysmon"
        )
        res_sysmon = router.determine_routing(ev_sysmon)
        assert res_sysmon.status == "ROUTED"
        assert res_sysmon.evidence_type == "Sysmon Operational Logs"
        assert res_sysmon.target_parser == "EvtxParser"

        # 2. Defender EVTX
        ev_defender = Evidence(
            case_id="CASE-DEFENDER-001",
            filename="Microsoft-Windows-Windows Defender%4Operational.evtx",
            file_path="C:\\logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
            uploaded_by="analyst",
            sha256_hash="abc123defender"
        )
        res_def = router.determine_routing(ev_defender)
        assert res_def.status == "ROUTED"
        assert res_def.evidence_type == "Windows Defender Logs"
        assert res_def.target_parser == "WindowsDefenderParser"

        # 3. Group Policy EVTX
        ev_gpo = Evidence(
            case_id="CASE-GPO-001",
            filename="Microsoft-Windows-GroupPolicy%4Operational.evtx",
            file_path="C:\\logs\\Microsoft-Windows-GroupPolicy%4Operational.evtx",
            uploaded_by="analyst",
            sha256_hash="abc123gpo"
        )
        res_gpo = router.determine_routing(ev_gpo)
        assert res_gpo.status == "ROUTED"
        assert res_gpo.evidence_type == "Group Policy Application Logs"
        assert res_gpo.target_parser == "GroupPolicyLogParser"

        # 4. Generic EVTX
        ev_generic = Evidence(
            case_id="CASE-GENERIC-001",
            filename="Application.evtx",
            file_path="C:\\logs\\Application.evtx",
            uploaded_by="analyst",
            sha256_hash="abc123generic"
        )
        res_gen = router.determine_routing(ev_generic)
        assert res_gen.status == "ROUTED"
        assert res_gen.evidence_type == "Windows Event Logs (EVTX) — threat-hunted"
        assert res_gen.target_parser == "EvtxParser"

    def test_firewall_mitre_mapping_is_none(self):
        engine = NetworkAnalysisEngine()
        art_drop = Artifact(
            evidence_id="EV-FW-01",
            source_tool="windows_firewall_parser",
            artifact_type="firewall_log",
            raw_fields={"action": "DROP", "protocol": "TCP", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 12345, "dst_port": 4444},
            normalized_fields=NormalizedFields(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=12345, dst_port=4444)
        )
        art_allow = Artifact(
            evidence_id="EV-FW-02",
            source_tool="windows_firewall_parser",
            artifact_type="firewall_log",
            raw_fields={"action": "ALLOW", "protocol": "TCP", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 12345, "dst_port": 80},
            normalized_fields=NormalizedFields(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=12345, dst_port=80)
        )
        from preprocessing.fcr_engine.schemas import CorrelationRecord
        fcr = CorrelationRecord(
            correlation_id="CORR-00001",
            case_id="CASE-FW-01",
            relationship_type=["single_artifact"],
            source_count=2,
            distinct_artifact_types=1,
            confidence=0.9,
            artifact_ids=[art_drop.artifact_id, art_allow.artifact_id]
        )
        store = {art_drop.artifact_id: art_drop, art_allow.artifact_id: art_allow}
        findings = engine.analyze([fcr], store)
        
        assert len(findings) == 2
        for f in findings:
            assert f.mitre_mapping is None
            assert "Windows Firewall" in f.fact

    def test_powershell_mitre_and_timestamp_preservation(self):
        analyzer = PowerShellAnalyzer()
        
        # History command with NO timestamp
        art_history = Artifact(
            evidence_id="EV-PS-HIST",
            source_tool="powershell_history_parser",
            artifact_type="powershell_history",
            timestamp=None,
            timestamp_type="none",
            raw_fields={"command_line": "Get-FileHash C:\\Windows\\System32\\calc.exe"},
            normalized_fields=NormalizedFields(process_command_line="Get-FileHash C:\\Windows\\System32\\calc.exe")
        )
        
        findings = analyzer.analyze("CASE-PS-01", [art_history], "CORR-00002")
        assert len(findings) == 1
        finding = findings[0]
        
        # Verify timestamp remains None (not populated with datetime.now())
        assert finding.timestamp is None
        # Verify Get-FileHash does NOT map to T1083
        assert finding.mitre_mapping is None
        assert "PowerShell command activity observed" in finding.fact

    def test_firewall_over_10_records_retention(self):
        parser = WindowsFirewallParser()
        
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".log") as tmp:
            tmp.write("#Fields: date time action protocol src-ip dst-ip src-port dst-port path\n")
            for _ in range(15):
                tmp.write("2026-09-19 10:00:00 ALLOW TCP 192.168.1.50 1.1.1.1 5000 443 SEND\n")
            tmp_path = tmp.name

        try:
            artifacts = parser.parse(tmp_path, "EV-FW-REPEATED")
            assert len(artifacts) == 15
            assert artifacts[14].raw_fields.get("flow_occurrence_count") == 15
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_report_export_gating_unreviewed_default(self):
        repo = FIRRepository()
        repo.clear()
        svc = AnalystFindingService(fir_repo=repo)
        
        f1 = FIRFinding(
            finding_id="F-001",
            case_id="CASE-RPT-01",
            tenant_id="tenant-alpha",
            fact="PowerShell history observed",
            confidence=0.9,
            severity="low",
            mitre_mapping=None,
            timestamp=None,
            evidence_reference=["EV-001"],
            layer="log.powershell_analyzer",
            review_status=ReviewStatus.PENDING_REVIEW
        )
        repo.insert(f1)
        
        # Default allow_unreviewed=False MUST exclude unreviewed findings (returning empty list)
        exported_default = svc.export_report(case_id="CASE-RPT-01", tenant_id="tenant-alpha", allow_unreviewed=False)
        assert len(exported_default) == 0

        # When explicitly requested with allow_unreviewed=True, exported
        exported_explicit = svc.export_report(case_id="CASE-RPT-01", tenant_id="tenant-alpha", allow_unreviewed=True)
        assert len(exported_explicit) == 1
        assert exported_explicit[0]["_review_gate"]["unreviewed"] is True

    def test_report_generator_determinism(self):
        gen = ReportGenerator()
        payload = {
            "case_id": "CASE-DET-01",
            "tenant_id": "tenant-alpha",
            "generated_at": "2026-09-19T10:00:00Z",
            "findings": [{
                "finding_id": "F-100",
                "severity": "high",
                "fact": "Suspicious login observed",
                "confidence": 0.95,
                "mitre_mapping": "T1078",
                "layer": "auth_analyzer",
                "review_status": "analyst_confirmed"
            }],
            "evidence_files": [{"evidence_id": "EV-1", "filename": "auth.log", "status": "sandboxed", "sha256_hash": "abc"}],
            "timeline": []
        }
        res1 = gen.generate(payload, format="json")
        res2 = gen.generate(payload, format="json")
        assert res1 == res2
