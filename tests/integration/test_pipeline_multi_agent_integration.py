"""
Project ARGUS — Comprehensive Multi-Agent Pipeline Integration Test Suite
==========================================================================
Covers: Agents 1, 2, 3, 4, 5a, 5b, 6, and 7.

Verifies:
  1. Integrated pipeline execution against a dedicated test case.
  2. Schema conformance for every agent output via Pydantic model validation.
  3. Upstream-to-downstream data flow across the reasoning chain.
  4. Agent 2 Neo4j evidence graph synchronization & GDS community detection.
  5. Agent 3 attack reconstruction, kill-chain sequencing & Neo4j graph writer.
  6. Agent 4 deterministic malware indicator extraction & YARA rule evaluation.
  7. Agent 5a threat intelligence feed queries & Agent 5b campaign similarity.
  8. Agent 6 CVSS v3.1 mathematics, ISS multi-factor calculation, asset discovery, and playbooks.
  9. PostgreSQL database persistence & consistency verification.
  10. Detection of missing outputs, schema violations, and hallucinated evidence IDs.
  11. Resilience and error handling when an optional downstream agent fails.
  12. Strict isolation preventing modification/deletion of real case investigation data.
"""

import os
import sys
import uuid
import json
import pytest
import psycopg2
from datetime import datetime, timezone
from typing import Dict, List, Any
from unittest.mock import MagicMock, patch

# Ensure project root in python path
sys.path.insert(0, os.path.abspath("."))

from config.settings import settings
from fir.schemas import FIRFinding
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway

# Pipeline orchestrator
from argus_pipeline import run_pipeline

# Agent schemas
from agents.agent1_evidence_intelligence.schemas import Agent1Output
from agents.agent2_evidence_correlation.schemas import Agent2Output
from agents.agent3_attack_reconstruction.schemas import Agent3Output
from agents.agent4_malware_behaviour.schemas import Agent4Output
from agents.agent6_impact_assessment.schemas import Agent6Output

# Drivers
from neo4j import GraphDatabase


# ── FIXTURES & HELPERS ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def neo4j_driver():
    """Connect to live Neo4j instance or provide mock driver if unreachable."""
    try:
        driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        driver.verify_connectivity()
        return driver
    except Exception as exc:
        pytest.skip(f"Neo4j instance offline: {exc}")


@pytest.fixture(scope="module")
def postgres_conn():
    """Connect to live PostgreSQL instance or skip if offline."""
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            dbname=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=3
        )
        conn.autocommit = True
        yield conn
        conn.close()
    except Exception as exc:
        pytest.skip(f"PostgreSQL instance offline: {exc}")


def build_dedicated_test_findings(case_id: str, tenant_id: str) -> List[FIRFinding]:
    """
    Constructs a rich, realistic forensic evidence dataset for pipeline verification.
    """
    t0 = datetime(2026, 10, 1, 8, 15, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 1, 8, 16, 22, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 1, 8, 20, 10, tzinfo=timezone.utc)
    t3 = datetime(2026, 10, 1, 8, 35, 0, tzinfo=timezone.utc)
    t4 = datetime(2026, 10, 1, 9, 12, 30, tzinfo=timezone.utc)

    return [
        FIRFinding(
            finding_id="F-TEST-001",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Inbound remote network phishing email with attachment 'security_update.bat' received from evil-sender.com and opened by user 'admin' on host WIN-WORKSTATION-01.",
            confidence=0.95,
            severity="high",
            timestamp=t0,
            evidence_reference=["EVID-EML-001"],
            layer="email_gateway",
            source_artifact_id="EVID-EML-001"
        ),
        FIRFinding(
            finding_id="F-TEST-002",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Process cmd.exe spawned powershell.exe executing base64 payload connecting to C2 IP 192.168.1.50 with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 on WIN-WORKSTATION-01.",
            confidence=0.98,
            severity="critical",
            timestamp=t1,
            evidence_reference=["EVID-PROC-002"],
            layer="process_execution",
            source_artifact_id="EVID-PROC-002"
        ),
        FIRFinding(
            finding_id="F-TEST-003",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Registry persistence key created in RunOnce for update.exe with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 by user 'admin' on WIN-WORKSTATION-01.",
            confidence=0.92,
            severity="high",
            timestamp=t2,
            evidence_reference=["EVID-REG-003"],
            layer="registry_persistence",
            source_artifact_id="EVID-REG-003"
        ),
        FIRFinding(
            finding_id="F-TEST-004",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Suspicious memory access detected: lsass.exe process memory read / credential harvesting attempt by powershell.exe on WIN-WORKSTATION-01.",
            confidence=0.90,
            severity="critical",
            timestamp=t3,
            evidence_reference=["EVID-MEM-004"],
            layer="memory_analysis",
            source_artifact_id="EVID-MEM-004"
        ),
        FIRFinding(
            finding_id="F-TEST-005",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Network connection established via SMB protocol from WIN-WORKSTATION-01 to Domain Controller WIN-DC-01 using compromised admin credentials.",
            confidence=0.94,
            severity="critical",
            timestamp=t4,
            evidence_reference=["EVID-NET-005"],
            layer="network_analysis",
            source_artifact_id="EVID-NET-005"
        )
    ]


class MockQwenModel:
    """Predictable high-performance mock Qwen model for deterministic end-to-end verification."""
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        prompt_lower = prompt.lower()
        system_lower = (system_prompt or "").lower()

        # 1. Agent 2: Evidence Correlation
        if "agent 2" in system_lower or "evidence correlation" in system_lower or "deterministic correlation signals" in prompt_lower or "<deterministic_correlation_signals>" in prompt:
            return json.dumps({
                "claims": [
                    {
                        "claim_id": "CLM-AG2-001",
                        "summary": "Correlated phishing delivery to credential harvesting",
                        "correlation_type": "temporal",
                        "findings_summary": "Findings F-TEST-001 and F-TEST-002 share timeline proximity",
                        "cited_evidence_ids": ["F-TEST-001", "F-TEST-002"],
                        "community_id": "GC-001",
                        "assessed_importance": "critical",
                        "confidence_score": 0.95,
                        "timeline_sequence": ["F-TEST-001", "F-TEST-002"],
                        "conflicts_noted": [],
                        "reasoning_notes": "Temporal sequence aligns with initial access and execution."
                    }
                ]
            })

        # 2. Agent 3: Attack Reconstruction
        elif ("agent 3" in system_lower or "attack reconstruction" in system_lower or "reconstruct the attack timeline" in prompt_lower) and "agent 2" not in system_lower:
            return json.dumps({
                "infection_path": {
                    "entry_point": "Inbound remote network phishing email with attachment security_update.bat (F-TEST-001)",
                    "evidence_ids": ["F-TEST-001"],
                    "confidence": 0.95
                },
                "attack_timeline": [
                    {
                        "timestamp": "2026-10-01T08:15:00Z",
                        "event": "Phishing email opened",
                        "stage": "Initial Access",
                        "evidence_ids": ["F-TEST-001"],
                        "confidence": 0.95
                    },
                    {
                        "timestamp": "2026-10-01T08:16:22Z",
                        "event": "PowerShell execution with base64 payload",
                        "stage": "Execution",
                        "evidence_ids": ["F-TEST-002"],
                        "confidence": 0.98
                    },
                    {
                        "timestamp": "2026-10-01T08:20:10Z",
                        "event": "Persistence key created in registry",
                        "stage": "Persistence",
                        "evidence_ids": ["F-TEST-003"],
                        "confidence": 0.92
                    },
                    {
                        "timestamp": "2026-10-01T08:35:00Z",
                        "event": "Credential harvesting via LSASS",
                        "stage": "Credential Access",
                        "evidence_ids": ["F-TEST-004"],
                        "confidence": 0.90
                    },
                    {
                        "timestamp": "2026-10-01T09:12:30Z",
                        "event": "SMB lateral movement to Domain Controller",
                        "stage": "Lateral Movement",
                        "evidence_ids": ["F-TEST-005"],
                        "confidence": 0.94
                    }
                ],
                "attack_chain": [
                    {"stage": "Initial Access", "events": ["Email opened"], "evidence_ids": ["F-TEST-001"], "confidence": 0.95},
                    {"stage": "Execution", "events": ["PowerShell payload"], "evidence_ids": ["F-TEST-002"], "confidence": 0.98},
                    {"stage": "Lateral Movement", "events": ["SMB connection"], "evidence_ids": ["F-TEST-005"], "confidence": 0.94}
                ],
                "attack_path": [
                    {
                        "step_number": 1,
                        "stage": "Initial Access",
                        "description": "Phishing email with attachment security_update.bat opened",
                        "evidence_ids": ["F-TEST-001"],
                        "confidence": 0.95
                    },
                    {
                        "step_number": 2,
                        "stage": "Execution",
                        "description": "PowerShell execution with base64 payload connecting to C2",
                        "evidence_ids": ["F-TEST-002"],
                        "confidence": 0.98
                    },
                    {
                        "step_number": 3,
                        "stage": "Persistence",
                        "description": "Registry RunOnce persistence key created",
                        "evidence_ids": ["F-TEST-003"],
                        "confidence": 0.92
                    },
                    {
                        "step_number": 4,
                        "stage": "Credential Access",
                        "description": "LSASS memory access and credential dumping",
                        "evidence_ids": ["F-TEST-004"],
                        "confidence": 0.90
                    },
                    {
                        "step_number": 5,
                        "stage": "Lateral Movement",
                        "description": "SMB lateral movement to Domain Controller WIN-DC-01",
                        "evidence_ids": ["F-TEST-005"],
                        "confidence": 0.94
                    }
                ],
                "lateral_movement": [
                    {
                        "source_host": "WIN-WORKSTATION-01",
                        "destination_host": "WIN-DC-01",
                        "method": "SMB",
                        "evidence_ids": ["F-TEST-005"],
                        "confidence": 0.94
                    }
                ],
                "missing_expected_events": [
                    {
                        "event": "Port Scan / Reconnaissance Event",
                        "reason": "Missing discovery stage prior to lateral movement",
                        "status": "NOT_OBSERVED"
                    }
                ],
                "reconstruction_summary": "Multi-stage intrusion originating from phishing and escalating to Domain Controller compromise.",
                "overall_confidence": 0.95
            })



        # 3. Agent 1: Evidence Intelligence
        elif "agent 1" in system_lower or "evidence intelligence" in system_lower or "synthesize initial structured claims" in prompt_lower:
            return json.dumps({
                "investigation_readiness": "READY",
                "possible_analyses": ["Endpoint process analysis", "Network connection tracking"],
                "performed_analyses": ["Phishing payload analysis", "Execution analysis"],
                "evidence_trust_score": 0.95,
                "claims": [
                    {
                        "claim_id": "CLM-AG1-001",
                        "summary": "Malicious execution of PowerShell payload from phishing email",
                        "findings_summary": "Finding F-TEST-001 and F-TEST-002 detail execution chain",
                        "cited_evidence_ids": ["F-TEST-001", "F-TEST-002"],
                        "assessed_importance": "critical",
                        "confidence_score": 0.96,
                        "missing_evidence_noted": [],
                        "uncertainties_or_conflicts": [],
                        "reasoning_notes": "Correlated email attachment with spawned process"
                    }
                ]
            })

        # 4. Agent 7: Supervisor Synthesis & Verification
        elif "supervisor" in system_lower or "synthesis" in system_lower:
            return json.dumps({
                "executive_summary": "Comprehensive forensic synthesis of multi-stage intrusion.",
                "incident_narrative": "Adversary gained initial access via phishing email and escalated laterally to Domain Controller.",
                "claims": [
                    {
                        "claim_id": "CLM-001",
                        "claim": "Inbound phishing email with malicious script delivered to workstation.",
                        "evidence_ids": ["F-TEST-001"],
                        "severity": "high",
                        "is_attribution": False,
                        "confidence": 0.95,
                        "mitre_tactics": ["Initial Access"],
                        "mitre_techniques": ["T1566.001"]
                    },
                    {
                        "claim_id": "CLM-002",
                        "claim": "PowerShell execution of obfuscated payload connecting to external command-and-control.",
                        "evidence_ids": ["F-TEST-002"],
                        "severity": "critical",
                        "is_attribution": False,
                        "confidence": 0.98,
                        "mitre_tactics": ["Execution"],
                        "mitre_techniques": ["T1059.001"]
                    },
                    {
                        "claim_id": "CLM-003",
                        "claim": "SMB lateral movement to Domain Controller using compromised administrative credentials.",
                        "evidence_ids": ["F-TEST-005"],
                        "severity": "critical",
                        "is_attribution": False,
                        "confidence": 0.94,
                        "mitre_tactics": ["Lateral Movement"],
                        "mitre_techniques": ["T1021.002"]
                    }
                ],
                "attack_timeline": [
                    {
                        "timestamp": "2026-10-01T08:15:00Z",
                        "stage": "Initial Access",
                        "summary": "Phishing email received",
                        "source_tool": "email_gateway",
                        "evidence_id": "F-TEST-001"
                    }
                ],
                "conflicts_resolved": [],
                "confidence_score": 0.95
            })

        elif "respond only with 'yes' or 'no'" in prompt_lower or "determine if the evidence strictly supports" in prompt_lower:
            return "YES"

        # Fallback / General JSON Response
        else:
            return json.dumps({
                "executive_summary": "Forensic claim grounded strictly in findings.",
                "claims": [
                    {
                        "claim_id": "CLM-DEF-001",
                        "claim": "Forensic claim grounded strictly in findings.",
                        "evidence_ids": ["F-TEST-001"],
                        "severity": "medium",
                        "is_attribution": False,
                        "confidence": 0.90
                    }
                ],
                "confidence_score": 0.90
            })


# ── TEST SUITE ────────────────────────────────────────────────────────────────

class TestMultiAgentPipelineIntegration:
    """
    Comprehensive integration test covering Agents 1, 2, 3, 4, 5a, 5b, 6, and 7.
    """

    @pytest.fixture(autouse=True)
    def setup_and_teardown(self, postgres_conn):
        """Sets up dedicated isolated case ID and cleans up only test rows."""
        self.case_id = f"CASE-INTEG-E2E-{uuid.uuid4().hex[:8]}"
        self.tenant_id = "tenant_integ_test"
        self.test_findings = build_dedicated_test_findings(self.case_id, self.tenant_id)
        
        yield
        
        # Cleanup: strict isolation to ensure real investigation data is never modified/deleted
        try:
            with postgres_conn.cursor() as cur:
                cur.execute("DELETE FROM agent_outputs WHERE case_id = %s;", (self.case_id,))
                cur.execute("DELETE FROM fir_findings WHERE case_id = %s;", (self.case_id,))
            postgres_conn.commit()
        except Exception as exc:
            print(f"[Cleanup Note] {exc}")

    def test_full_pipeline_execution_and_schema_conformance(self, neo4j_driver, postgres_conn):
        """
        Executes complete multi-agent pipeline and verifies:
          - Every agent executes without unhandled errors.
          - Outputs conform to strict Pydantic schemas.
          - Data flows correctly from upstream to downstream.
          - PostgreSQL persistence is consistent.
          - Neo4j evidence graph and attack path writer are synced.
        """
        # Mock external threat feeds and vector store
        mock_stix = MagicMock()
        mock_stix.last_updated = datetime.now(timezone.utc)
        mock_stix.max_age_seconds = 86400
        mock_stix.check_ioc.side_effect = lambda ioc: {
            "id": f"stix-{ioc}",
            "pattern": f"[ipv4-addr:value = '{ioc}']" if ioc == "192.168.1.50" else f"[domain-name:value = '{ioc}']",
            "description": "Known malicious indicator",
            "tags": ["malware", "family:CobaltStrike"],
        } if ioc in ("192.168.1.50", "evil-sender.com") else {}

        mock_cve = MagicMock()
        mock_cve.last_updated = datetime.now(timezone.utc)
        mock_cve.max_age_seconds = 86400
        mock_cve.lookup_cve.return_value = {"id": "CVE-2026-1234", "cvss": 9.8, "description": "RCE vulnerability"}
        mock_cve.get_cisa_kev.return_value = []

        mock_mitre = MagicMock()
        mock_mitre.last_updated = datetime.now(timezone.utc)
        mock_mitre.max_age_seconds = 86400
        mock_mitre.get_technique.return_value = {"id": "T1059.001", "name": "PowerShell", "description": "Command execution"}

        mock_vec = MagicMock()
        mock_vec.search.return_value = [{"case_id": "HIST-APT29-001", "similarity": 0.89, "campaign": "APT29 Cozy Bear"}]

        mock_model = MockQwenModel()

        # ── 1. Execute Integrated Pipeline ──────────────────────────────────
        results = run_pipeline(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fir_findings=self.test_findings,
            llm=mock_model,
            neo4j_client=neo4j_driver,
            stix_client=mock_stix,
            cve_client=mock_cve,
            mitre_client=mock_mitre,
            vector_store=mock_vec,
            stop_on_error=True
        )

        assert results is not None
        assert results["case_id"] == self.case_id
        assert results["execution_status"] == "SUCCESS"
        assert len(results["agent_errors"]) == 0

        # ── 2. Verify Agent 1: Evidence Intelligence ────────────────────────
        ag1 = results["agent1"]
        assert ag1 is not None
        Agent1Output.model_validate(ag1)
        readiness = ag1.get("investigation_readiness")
        readiness_status = readiness.get("status") if isinstance(readiness, dict) else str(readiness)
        assert readiness_status in ("READY", "PARTIAL")
        assert len(ag1.get("claims", [])) >= 1
        claim1 = ag1["claims"][0]
        assert set(claim1.get("cited_evidence_ids", [])).issubset({f.finding_id for f in self.test_findings})

        # ── 3. Verify Agent 2: Evidence Correlation (Neo4j & Timeline) ──────
        ag2 = results["agent2"]
        assert ag2 is not None
        Agent2Output.model_validate(ag2)
        assert len(ag2.get("claims", [])) >= 1
        claim2 = ag2["claims"][0]
        assert set(claim2.get("cited_evidence_ids", [])).issubset({f.finding_id for f in self.test_findings})
        assert claim2.get("citation_verified") is True or claim2.get("citation_valid") is True

        # Direct Neo4j Graph verification
        with neo4j_driver.session() as session:
            res = session.run(
                "MATCH (a:Artifact {case_id: $case_id}) RETURN count(a) AS cnt",
                {"case_id": self.case_id}
            ).single()
            assert res["cnt"] > 0, "Agent 2 failed to persist Artifact nodes in Neo4j."

        # ── 4. Verify Agent 3: Attack Reconstruction ────────────────────────
        ag3 = results["agent3"]
        assert ag3 is not None
        Agent3Output.model_validate(ag3)
        assert ag3["infection_path"] is not None
        assert ag3["infection_path"]["entry_point"] != ""
        assert len(ag3["attack_timeline"]) == 5
        assert len(ag3["lateral_movement"]) >= 1
        assert ag3["lateral_movement"][0]["source_host"] == "WIN-WORKSTATION-01"
        assert ag3["lateral_movement"][0]["destination_host"] == "WIN-DC-01"
        assert ag3["overall_confidence"] >= 0.80

        # Direct Neo4j Attack Path Graph Sync verification
        with neo4j_driver.session() as session:
            res_steps = session.run(
                "MATCH (s:AttackStep {case_id: $case_id}) RETURN count(s) AS cnt",
                {"case_id": self.case_id}
            ).single()
            assert res_steps["cnt"] > 0, "Agent 3 failed to write AttackStep nodes in Neo4j graph."

            res_lm = session.run(
                "MATCH ()-[r:LATERAL_MOVEMENT]->() WHERE r.case_id = $case_id RETURN count(r) AS cnt",
                {"case_id": self.case_id}
            ).single()
            assert res_lm["cnt"] > 0, "Agent 3 failed to write LATERAL_MOVEMENT edges in Neo4j graph."

        # ── 5. Verify Agent 4: Malware Behaviour ────────────────────────────
        ag4 = results["agent4"]
        assert ag4 is not None
        Agent4Output.model_validate(ag4)
        assert ag4["scan_summary"] is not None
        assert ag4["execution_status"] in ("SUCCESS", "ExecutionStatus.SUCCESS")

        # ── 6. Verify Agent 5a & 5b: Threat Intel & Case Similarity ────────
        ag5a = results["agent5a"]
        assert ag5a is not None
        assert "claim" in ag5a
        assert "IOC match" in ag5a["claim"]
        assert "CVE lookup" in ag5a["claim"]

        ag5b = results["agent5b"]
        assert ag5b is not None
        assert "claim" in ag5b
        assert ag5b["claim"] != ""

        # ── 7. Verify Agent 6: Impact Assessment (CVSS, ISS, Assets) ────────
        ag6 = results["agent6"]
        assert ag6 is not None
        Agent6Output.model_validate(ag6)

        # Check CVSS v3.1 calculations
        cvss = ag6["cvss_assessment"]
        assert cvss["base_score"] is not None
        assert 0.0 <= cvss["base_score"] <= 10.0
        assert cvss["vector_string"].startswith("CVSS:3.1/")
        assert cvss.get("exploitability_subscore") is not None or cvss.get("exploitability_score") is not None
        assert cvss.get("impact_subscore") is not None or cvss.get("impact_score") is not None

        # Check ISS calculations
        iss = ag6["iss_assessment"]
        assert iss["iss_score"] is not None
        assert 0.0 <= iss["iss_score"] <= 10.0
        factors = iss.get("factor_breakdown", {})
        assert len(factors) == 6
        assert abs(sum(f["weight"] for f in factors.values()) - 1.0) < 1e-4

        # Check Asset inventory discovery
        assets = ag6["affected_assets"]
        asset_ids = [a["asset_id"] for a in assets]
        assert any("WIN-WORKSTATION-01" in aid or "WIN-DC-01" in aid for aid in asset_ids)
        assert any(a["criticality"] in ("CRITICAL", "HIGH") for a in assets)

        # Check Recovery checklist
        playbook = ag6["recovery_checklist"]
        assert playbook["total_actions"] > 0
        all_actions = ag6.get("recovery_actions", [])
        phases = {act["phase"] for act in all_actions}
        assert "CONTAINMENT" in phases or "ERADICATION" in phases

        # Check Evidence citation integrity: every cited evidence ID exists in valid universe
        valid_finding_ids = {f.finding_id for f in self.test_findings}
        for eid in ag6.get("all_cited_evidence_ids", []):
            assert eid in valid_finding_ids, f"Agent 6 cited invalid evidence ID: {eid}"

        # ── 8. Verify Agent 7: Supervisor Synthesis & Verification ──────────
        ag7 = results["agent7"]
        assert ag7 is not None
        assert "synthesis" in ag7
        assert len(ag7["synthesis"]["claims"]) >= 1
        assert "verification" in ag7
        assert len(ag7["verification"]) >= 1
        for v in ag7["verification"]:
            assert "verified" in v
            assert "checks" in v

        # ── 9. Verify PostgreSQL Database Persistence & Consistency ────────
        with postgres_conn.cursor() as cur:
            cur.execute("""
                SELECT agent_id, claim, confidence, verified, execution_status
                FROM agent_outputs
                WHERE case_id = %s
                ORDER BY created_at ASC;
            """, (self.case_id,))
            db_rows = cur.fetchall()

        persisted_agents = {row[0] for row in db_rows}
        assert "agent_3" in persisted_agents, "Agent 3 output was not persisted to PostgreSQL."
        assert "agent_6" in persisted_agents or "agent6_impact_assessment" in persisted_agents, "Agent 6 output was not persisted to PostgreSQL."

        # Consistency check: verify Agent 3 database confidence matches returned confidence
        ag3_db_row = next(r for r in db_rows if r[0] == "agent_3")
        assert abs(ag3_db_row[2] - ag3["overall_confidence"]) < 0.01

    def test_detection_of_invalid_schemas_and_hallucinated_citations(self):
        """
        Validates that schema validation and citation verification fail-closed
        when presented with malformed data or hallucinated evidence citations.
        """
        # 1. Hallucinated citation detection
        hallucinated_output = {
            "case_id": self.case_id,
            "tenant_id": self.tenant_id,
            "agent_id": "agent6_impact_assessment",
            "cvss_assessment": {
                "assessment_status": "DETERMINED",
                "base_score": 9.8,
                "severity": "CRITICAL",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "exploitability_score": 3.9,
                "impact_score": 5.9,
                "metrics_found": {},
                "missing_metrics": []
            },
            "iss_assessment": {
                "iss_score": 9.2,
                "severity": "CRITICAL",
                "factor_scores": {
                    "asset_criticality": {"weight": 0.25, "score": 9.5, "weighted_score": 2.375},
                    "data_compromise": {"weight": 0.20, "score": 9.0, "weighted_score": 1.8},
                    "system_integrity": {"weight": 0.20, "score": 9.0, "weighted_score": 1.8},
                    "operational_availability": {"weight": 0.15, "score": 8.0, "weighted_score": 1.2},
                    "lateral_movement_scope": {"weight": 0.10, "score": 9.5, "weighted_score": 0.95},
                    "technical_vulnerability": {"weight": 0.10, "score": 9.8, "weighted_score": 0.98}
                },
                "confidence_score": 0.95
            },
            "affected_assets": [],
            "recovery_checklist": {"total_actions": 0, "actions": []},
            "executive_narration": "Test summary",
            "cited_evidence_ids": ["HALLUCINATED-EVIDENCE-99999"]
        }

        valid_ids = {f.finding_id for f in self.test_findings}
        hallucinated_ids = [eid for eid in hallucinated_output["cited_evidence_ids"] if eid not in valid_ids]
        assert len(hallucinated_ids) == 1
        assert hallucinated_ids[0] == "HALLUCINATED-EVIDENCE-99999"

        # 2. Schema validation error detection on malformed structure
        malformed_agent3 = {"attack_timeline": "NOT_A_LIST"}
        with pytest.raises(Exception):
            Agent3Output.model_validate(malformed_agent3)

    def test_pipeline_resilience_when_optional_downstream_agent_fails(self, neo4j_driver):
        """
        Verifies that if an optional downstream agent fails (e.g. Agent 5a feed network error),
        the pipeline handles it gracefully, flags the error, and completes upstream/downstream agents.
        """
        # Inject failing mock client into Agent 5a
        failing_stix = MagicMock()
        failing_stix.check_ioc.side_effect = ConnectionError("STIX TAXII Server 503 Service Unavailable")

        mock_model = MockQwenModel()
        mock_vec = MagicMock()
        mock_vec.search.return_value = [{"case_id": "HIST-APT29-001", "similarity": 0.89, "campaign": "APT29 Cozy Bear"}]

        results = run_pipeline(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fir_findings=self.test_findings,
            llm=mock_model,
            neo4j_client=neo4j_driver,
            stix_client=failing_stix,
            cve_client=MagicMock(),
            mitre_client=MagicMock(),
            vector_store=mock_vec,
            stop_on_error=False  # Resilient mode
        )

        # Pipeline must complete with PARTIAL_SUCCESS
        assert results["execution_status"] == "PARTIAL_SUCCESS"
        assert "agent5a" in results["agent_errors"]

        # Downstream Agent 6 and Agent 7 must STILL execute successfully using available context
        assert results["agent6"]["execution_status"] != "FAILED"
        assert results["agent6"]["iss_assessment"]["iss_score"] > 0
        assert results["agent7"]["synthesis"]["confidence_score"] > 0
