"""
Integration Test: Verifying Agent 2 Reception of Sigma & YARA Findings
========================================================================
Validates that Agent 2's pipeline explicitly receives:
- Sigma findings & YARA findings
- Evidence IDs & Artifact IDs
- Timestamps
- Source/rule information & layer provenance
- Severity & calibrated Confidence
- Correlations involving those findings (Temporal Clusters & Knowledge Graph)
"""

import pytest
from datetime import datetime, timezone

from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding, finding_to_fir
from forensic_analysis.rules.sigma_engine import SigmaRuleEngine
from forensic_analysis.rules.yara_engine import YaraRuleEngine, YARA_AVAILABLE
from sanitization.gateway import SanitizationGateway, SanitizedAgentContext
from agents.agent2_evidence_correlation.timeline import TimelineBuilder


def test_agent2_receives_sigma_and_yara_findings(tmp_path):
    # ── 1. Create Sigma Rule & Evaluate ─────────────────────────────────────
    sigma_yaml = """
title: Mimikatz LSASS Dump Test
id: sima-mimikatz-01
level: high
tags:
  - attack.t1003.001
description: Detects mimikatz LSASS dumping
detection:
  selection:
    CommandLine|contains: 'logonpasswords'
  condition: selection
"""
    sigma_file = tmp_path / "test_sigma.yml"
    sigma_file.write_text(sigma_yaml, encoding="utf-8")

    sigma_engine = SigmaRuleEngine(rules_dir=str(tmp_path))

    t0 = datetime(2026, 10, 4, 1, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 4, 1, 5, 0, tzinfo=timezone.utc)

    sigma_art = Artifact(
        artifact_id="art-sigma-log-01",
        evidence_id="ev-disk-image-01",
        artifact_type="process_event",
        source_tool="sysmon",
        timestamp=t0,
        raw_fields={"CommandLine": "mimikatz.exe sekurlsa::logonpasswords"}
    )

    sigma_findings = sigma_engine.evaluate(
        case_id="CASE-AGENT2-01",
        artifacts=[sigma_art],
        fcr_ref="FCR-SIGMA-101"
    )
    assert len(sigma_findings) == 1
    sig_finding = sigma_findings[0]

    # ── 2. Create YARA Rule & Evaluate ──────────────────────────────────────
    yara_engine = YaraRuleEngine(rules_dir=str(tmp_path))
    yara_rule_str = """
rule Test_Yara_Malware
{
    meta:
        severity = "critical"
        confidence = "0.92"
        mitre_attack = "attack.t1055"
        description = "Test Malware String Match"
    strings:
        $s1 = "sekurlsa::logonpasswords"
    condition:
        $s1
}
"""
    yara_engine.add_rule_string(yara_rule_str, identifier="yara_test")

    if YARA_AVAILABLE:
        yara_findings = yara_engine.evaluate_bytes(
            case_id="CASE-AGENT2-01",
            artifact_id="art-yara-mem-01",
            data=b"sekurlsa::logonpasswords in process memory",
            evidence_ref="ev-mem-dump-01",
            source_name="lsass.dmp"
        )
    else:
        # Fallback Mock finding for test environment if yara-python is absent
        yara_findings = [
            Finding(
                case_id="CASE-AGENT2-01",
                fact="YARA rule 'Test_Yara_Malware' matched on 'lsass.dmp'",
                confidence=0.92,
                severity="critical",
                mitre_mapping="T1055",
                timestamp=datetime(2026, 10, 4, 1, 5, 0, tzinfo=timezone.utc),
                evidence_reference="ev-mem-dump-01",
                source_artifact_id="art-yara-mem-01",
                layer="yara.Test_Yara_Malware"
            )
        ]

    assert len(yara_findings) == 1
    yara_finding = yara_findings[0]
    yara_finding.timestamp = t1

    # ── 3. Convert Findings to FIRFindings ──────────────────────────────────
    fir_sigma = finding_to_fir(sig_finding)
    fir_yara = finding_to_fir(yara_finding)

    # ── 4. Pass through Sanitization Gateway for Agent 2 Context ───────────
    gateway = SanitizationGateway()
    ctx_sigma = gateway.sanitize_finding(fir_sigma)
    ctx_yara = gateway.sanitize_finding(fir_yara)

    # ── 5. Assert Agent 2 Context Completeness ──────────────────────────────
    # A) Sigma Context Assertions
    assert ctx_sigma.source_artifact_id == "art-sigma-log-01"
    assert "FCR-SIGMA-101" in ctx_sigma.evidence_reference
    assert ctx_sigma.layer == "sigma.sima-mimikatz-01"
    assert ctx_sigma.severity == "high"
    assert ctx_sigma.confidence == 0.88
    assert ctx_sigma.mitre_mapping.lower() in ("attack.t1003.001", "t1003.001")

    # XML Evidence Block Verification for Sigma
    xml_sig = ctx_sigma.xml_evidence_block
    assert 'finding_id="' in xml_sig
    assert 'layer="sigma.sima-mimikatz-01"' in xml_sig
    assert 'source_artifact_id="art-sigma-log-01"' in xml_sig
    assert 'evidence_reference="FCR-SIGMA-101"' in xml_sig
    assert 'severity="high"' in xml_sig
    assert 'confidence="0.88"' in xml_sig

    # B) YARA Context Assertions
    assert ctx_yara.source_artifact_id == "art-yara-mem-01"
    assert "ev-mem-dump-01" in ctx_yara.evidence_reference
    assert "yara.Test_Yara_Malware" in ctx_yara.layer
    assert ctx_yara.severity == "critical"
    assert ctx_yara.confidence == 0.92
    assert ctx_yara.mitre_mapping.lower() in ("attack.t1055", "t1055")

    # XML Evidence Block Verification for YARA
    xml_yara = ctx_yara.xml_evidence_block
    assert 'finding_id="' in xml_yara
    assert 'layer="yara.Test_Yara_Malware"' in xml_yara
    assert 'source_artifact_id="art-yara-mem-01"' in xml_yara
    assert 'evidence_reference="ev-mem-dump-01"' in xml_yara
    assert 'severity="critical"' in xml_yara
    assert 'confidence="0.92"' in xml_yara

    # ── 6. Deterministic Timeline Correlation Verification ─────────────────
    timeline_builder = TimelineBuilder(time_window_seconds=3600)
    sorted_findings, clusters = timeline_builder.build_timeline([fir_sigma, fir_yara])

    assert len(sorted_findings) == 2
    assert len(clusters) == 1  # Clustered within 1 hour window!
    cluster = clusters[0]
    assert fir_sigma.finding_id in cluster.finding_ids
    assert fir_yara.finding_id in cluster.finding_ids
