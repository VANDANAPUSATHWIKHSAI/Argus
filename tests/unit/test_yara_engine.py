"""
Unit tests for YaraRuleEngine — Binary/File YARA Pattern Matching
===================================================================
"""

import os
import pytest
from datetime import datetime, timezone

from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding
from forensic_analysis.rules.yara_engine import (
    YaraRuleEngine,
    YARA_AVAILABLE,
    BLOCKED_DISK_EXTENSIONS,
    SEVERITY_TO_CONFIDENCE
)


def test_yara_engine_bytes_matching(tmp_path):
    engine = YaraRuleEngine(rules_dir=str(tmp_path))

    rule_str = """
rule Test_Malware_Sig
{
    meta:
        description = "Test Malware String Match"
        author = "Argus Test"
        severity = "critical"
        mitre_attack = "attack.t1055"

    strings:
        $a = "sekurlsa::logonpasswords"
        $b = "ReflectiveLoader"

    condition:
        $a or $b
}
"""
    success = engine.add_rule_string(rule_str, identifier="test_rule")
    if not YARA_AVAILABLE:
        pytest.skip("yara-python package not installed")

    assert success is True

    # 1. Matching byte payload
    match_payload = b"Sample executable payload with sekurlsa::logonpasswords embedded in binary."
    findings = engine.evaluate_bytes(
        case_id="CASE-YARA-01",
        artifact_id="art-mem-01",
        data=match_payload,
        evidence_ref="FCR-YARA-01",
        source_name="mem_dump.bin"
    )

    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.case_id == "CASE-YARA-01"
    assert finding.source_artifact_id == "art-mem-01"
    assert finding.confidence == SEVERITY_TO_CONFIDENCE["critical"]
    assert finding.severity == "critical"
    assert finding.mitre_mapping == "attack.t1055"
    assert "yara.Test_Malware_Sig" in finding.layer
    assert finding.metadata["total_string_matches"] == 1


def test_yara_engine_disk_safety_guard(tmp_path):
    engine = YaraRuleEngine(rules_dir=str(tmp_path))

    # Create dummy raw disk file
    raw_disk_file = tmp_path / "system_disk.vmdk"
    raw_disk_file.write_bytes(b"sekurlsa::logonpasswords raw disk data " * 100)

    # Adding a rule
    rule_str = """
rule Test_Disk_Safety
{
    strings:
        $a = "sekurlsa::logonpasswords"
    condition:
        $a
}
"""
    engine.add_rule_string(rule_str, identifier="disk_test")
    if not YARA_AVAILABLE:
        pytest.skip("yara-python package not installed")

    # Scanning raw disk image file should be blocked by disk safety guard
    findings = engine.evaluate_file(
        case_id="CASE-DISK-01",
        artifact_id="art-disk-01",
        file_path=str(raw_disk_file),
        evidence_ref="FCR-DISK-01"
    )

    # Should be empty because .vmdk extension is blocked!
    assert len(findings) == 0


def test_yara_engine_file_matching(tmp_path):
    engine = YaraRuleEngine(rules_dir=str(tmp_path))

    sample_bin = tmp_path / "suspicious_payload.exe"
    sample_bin.write_bytes(b"MZ header... ReflectiveLoader embedded payload data...")

    rule_str = """
rule Test_File_Reflective
{
    meta:
        severity = "high"
        confidence = "0.88"
    strings:
        $ref = "ReflectiveLoader"
    condition:
        $ref
}
"""
    engine.add_rule_string(rule_str, identifier="file_test")
    if not YARA_AVAILABLE:
        pytest.skip("yara-python package not installed")

    findings = engine.evaluate_file(
        case_id="CASE-FILE-01",
        artifact_id="art-file-01",
        file_path=str(sample_bin),
        evidence_ref="FCR-FILE-01"
    )

    assert len(findings) == 1
    assert findings[0].confidence == 0.88
    assert findings[0].severity == "high"
    assert findings[0].source_artifact_id == "art-file-01"
