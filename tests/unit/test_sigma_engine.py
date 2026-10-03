"""
Unit tests for SigmaRuleEngine — Pure-Python Sigma Rule Engine
==============================================================
"""

import os
import pytest
from datetime import datetime, timezone

from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding
from forensic_analysis.rules.sigma_engine import SigmaRuleEngine, LEVEL_TO_CONFIDENCE


def test_sigma_engine_basic_match(tmp_path):
    # 1. Create a temporary Sigma rule
    rule_yaml = """
title: Test Mimikatz Execution
id: test-mimikatz-rule-01
level: high
tags:
  - attack.t1003.001
  - attack.credential_access
description: Detects mimikatz LSASS dumping
detection:
  selection:
    Image|endswith: '\\mimikatz.exe'
    CommandLine|contains: 'logonpasswords'
  condition: selection
"""
    rule_file = tmp_path / "test_mimikatz.yml"
    rule_file.write_text(rule_yaml, encoding="utf-8")

    # 2. Instantiate SigmaRuleEngine pointing to temp dir
    engine = SigmaRuleEngine(rules_dir=str(tmp_path))
    assert len(engine.rules) == 1

    # 3. Create matching Artifact
    matching_art = Artifact(
        artifact_id="art-log-101",
        evidence_id="ev-test-101",
        artifact_type="process_event",
        source_tool="sysmon",
        timestamp=datetime.now(timezone.utc),
        raw_fields={
            "Image": "C:\\Windows\\Temp\\mimikatz.exe",
            "CommandLine": "mimikatz.exe sekurlsa::logonpasswords full",
        },
        normalized_fields={
            "process_name": "mimikatz.exe",
            "process_command_line": "mimikatz.exe sekurlsa::logonpasswords full",
        }
    )

    # 4. Create non-matching Artifact
    non_matching_art = Artifact(
        artifact_id="art-log-102",
        evidence_id="ev-test-102",
        artifact_type="process_event",
        source_tool="sysmon",
        timestamp=datetime.now(timezone.utc),
        raw_fields={
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "svchost.exe -k netsvcs",
        }
    )

    findings = engine.evaluate(
        case_id="CASE-SIGMA-01",
        artifacts=[matching_art, non_matching_art],
        fcr_ref="FCR-SIGMA-01"
    )

    # 5. Assertions
    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.case_id == "CASE-SIGMA-01"
    assert finding.source_artifact_id == "art-log-101"
    assert finding.confidence == LEVEL_TO_CONFIDENCE["high"]
    assert finding.confidence != 0.90  # Verify confidence is NOT blindly hardcoded to 0.90
    assert finding.severity == "high"
    assert finding.mitre_mapping.lower() in ("attack.t1003.001", "t1003.001")
    assert "sigma.test-mimikatz-rule-01" in finding.layer
    assert "mimikatz" in finding.fact.lower()


def test_sigma_engine_condition_logic(tmp_path):
    # Test 'or' and 'not' condition logic
    rule_yaml = """
title: Test PowerShell Encoded Or Bypass
id: test-ps-rule-02
level: critical
tags:
  - attack.t1059.001
description: Detects encoded powershell unless excluded
detection:
  selection_enc:
    CommandLine|contains: '-EncodedCommand'
  selection_b64:
    CommandLine|contains: ' -e '
  exclusion:
    User: 'SYSTEM'
  condition: (selection_enc or selection_b64) and not exclusion
"""
    rule_file = tmp_path / "test_ps.yml"
    rule_file.write_text(rule_yaml, encoding="utf-8")

    engine = SigmaRuleEngine(rules_dir=str(tmp_path))

    # Match: Encoded powershell by non-SYSTEM user
    art1 = Artifact(
        artifact_id="art-ps-1",
        evidence_id="ev-ps-1",
        artifact_type="powershell_event",
        source_tool="powershell",
        raw_fields={"CommandLine": "powershell.exe -EncodedCommand JABzAD0...", "User": "Administrator"}
    )

    # Excluded: Encoded powershell by SYSTEM user
    art2 = Artifact(
        artifact_id="art-ps-2",
        evidence_id="ev-ps-2",
        artifact_type="powershell_event",
        source_tool="powershell",
        raw_fields={"CommandLine": "powershell.exe -EncodedCommand JABzAD0...", "User": "SYSTEM"}
    )

    findings = engine.evaluate("CASE-02", [art1, art2], "FCR-02")
    assert len(findings) == 1
    assert findings[0].source_artifact_id == "art-ps-1"
    assert findings[0].confidence == LEVEL_TO_CONFIDENCE["critical"]
    assert findings[0].severity == "critical"
