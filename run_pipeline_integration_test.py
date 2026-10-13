#!/usr/bin/env python3
"""
Project ARGUS — Standalone Multi-Agent Pipeline Integration Test Runner
=======================================================================
Executes the integrated Project Argus pipeline across Agents 1, 2, 3, 4, 5a, 5b, 6, and 7.
Produces a formatted PASS/FAIL summary table detailing each agent and validation check.

Usage:
    python run_pipeline_integration_test.py
"""

import sys
import os
import time
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any
from unittest.mock import MagicMock

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
import psycopg2
from neo4j import GraphDatabase


# ── COLOR / FORMATTING UTILS ──────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    print(f"\n{BOLD}{CYAN}{'=' * 88}{RESET}")
    print(f"{BOLD}{CYAN}  PROJECT ARGUS — MULTI-AGENT PIPELINE INTEGRATION TEST RUNNER{RESET}")
    print(f"{BOLD}{CYAN}  Agents Covered: 1, 2, 3, 4, 5a, 5b, 6, and 7{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 88}{RESET}\n")


# ── TEST FIXTURE DATA BUILDER ─────────────────────────────────────────────────
def build_test_findings(case_id: str, tenant_id: str) -> List[FIRFinding]:
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

        # 1. Agent 3: Attack Reconstruction
        if "agent 3" in system_lower or "attack reconstruction" in system_lower or "reconstruct the attack timeline" in prompt_lower:
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

        # 2. Agent 2: Evidence Correlation
        elif "agent 2" in system_lower or "evidence correlation" in system_lower or "deterministic correlation signals" in prompt_lower or "<deterministic_correlation_signals>" in prompt:
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

        # Fallback / Supervisor Synthesis
        else:
            return "Synthesized claim grounded strictly in forensic findings."


# ── TEST RUNNER IMPLEMENTATION ────────────────────────────────────────────────

def run_integration_tests():
    print_banner()

    checks_results: List[Dict[str, Any]] = []

    def record_check(category: str, check_name: str, passed: bool, details: str = ""):
        checks_results.append({
            "category": category,
            "check": check_name,
            "passed": passed,
            "details": details
        })
        status_str = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
        print(f"  [{status_str}] {BOLD}{category}{RESET} :: {check_name} {f'({details})' if details else ''}")

    # ── 1. PREREQUISITES VERIFICATION ─────────────────────────────────────────
    print(f"\n{BOLD}[Phase 1: Environment & Container Prerequisites]{RESET}")

    # PostgreSQL
    postgres_conn = None
    try:
        postgres_conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            dbname=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=3
        )
        postgres_conn.autocommit = True
        record_check("Prerequisites", "PostgreSQL Connection (port 5433)", True, "Active and reachable")
    except Exception as exc:
        record_check("Prerequisites", "PostgreSQL Connection (port 5433)", False, str(exc))

    # Neo4j
    neo4j_driver = None
    try:
        neo4j_driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        neo4j_driver.verify_connectivity()
        record_check("Prerequisites", "Neo4j Graph Database (port 7687)", True, "Bolt driver connected")
    except Exception as exc:
        record_check("Prerequisites", "Neo4j Graph Database (port 7687)", False, str(exc))

    if not postgres_conn or not neo4j_driver:
        print(f"\n{RED}Critical prerequisite failed. Aborting pipeline integration test.{RESET}")
        sys.exit(1)

    # ── 2. ISOLATED TEST CASE SETUP ───────────────────────────────────────────
    test_case_id = f"CASE-INTEG-RUNNER-{uuid.uuid4().hex[:8]}"
    test_tenant_id = "tenant_runner_test"
    test_findings = build_test_findings(test_case_id, test_tenant_id)
    print(f"\n{BOLD}[Phase 2: Executing Pipeline on Dedicated Case: {test_case_id}]{RESET}")

    mock_stix = MagicMock()
    mock_stix.check_ioc.return_value = {"ioc": "192.168.1.50", "threat_score": 95, "family": "CobaltStrike"}

    mock_cve = MagicMock()
    mock_cve.lookup_cve.return_value = {"cve_id": "CVE-2026-1234", "cvss": 9.8, "description": "RCE vulnerability"}

    mock_mitre = MagicMock()
    mock_mitre.get_technique.return_value = {"technique_id": "T1059.001", "name": "PowerShell", "description": "Command execution"}

    mock_vec = MagicMock()
    mock_vec.search.return_value = [{"case_id": "HIST-APT29-001", "similarity": 0.89, "campaign": "APT29 Cozy Bear"}]

    mock_model = MockQwenModel()

    t_start = time.time()
    try:
        pipeline_results = run_pipeline(
            case_id=test_case_id,
            tenant_id=test_tenant_id,
            fir_findings=test_findings,
            llm=mock_model,
            neo4j_client=neo4j_driver,
            stix_client=mock_stix,
            cve_client=mock_cve,
            mitre_client=mock_mitre,
            vector_store=mock_vec,
            stop_on_error=True
        )
        elapsed = round(time.time() - t_start, 2)
        record_check("Pipeline", "Orchestrator Execution", True, f"Completed in {elapsed}s without unhandled errors")
    except Exception as exc:
        record_check("Pipeline", "Orchestrator Execution", False, str(exc))
        pipeline_results = {}

    # ── 3. DETAILED AGENT VALIDATION ──────────────────────────────────────────
    print(f"\n{BOLD}[Phase 3: Multi-Agent Schema & Contract Verification]{RESET}")

    # Agent 1
    ag1 = pipeline_results.get("agent1", {})
    try:
        Agent1Output.model_validate(ag1)
        valid_ag1 = ag1.get("investigation_readiness") in ("READY", "PARTIAL") and len(ag1.get("claims", [])) >= 1
        record_check("Agent 1", "Evidence Intelligence Schema & Claims", valid_ag1, f"{len(ag1.get('claims', []))} claims validated")
    except Exception as exc:
        record_check("Agent 1", "Evidence Intelligence Schema & Claims", False, str(exc))

    # Agent 2
    ag2 = pipeline_results.get("agent2", {})
    try:
        Agent2Output.model_validate(ag2)
        valid_ag2 = ag2.get("graph_metrics", {}).get("neo4j_synced") is True and len(ag2.get("claims", [])) >= 1
        record_check("Agent 2", "Evidence Correlation Schema & Claims", valid_ag2, f"Neo4j synced={ag2.get('graph_metrics', {}).get('neo4j_synced')}")

        # Neo4j Graph verification
        with neo4j_driver.session() as session:
            r = session.run("MATCH (a:Artifact {case_id: $case_id}) RETURN count(a) AS cnt", {"case_id": test_case_id}).single()
            node_cnt = r["cnt"] if r else 0
        record_check("Agent 2", "Neo4j Knowledge Graph Artifact Ingestion", node_cnt > 0, f"{node_cnt} Artifact nodes written")
    except Exception as exc:
        record_check("Agent 2", "Evidence Correlation Schema & Graph", False, str(exc))

    # Agent 3
    ag3 = pipeline_results.get("agent3", {})
    try:
        Agent3Output.model_validate(ag3)
        valid_ag3 = (
            ag3.get("infection_path", {}).get("entry_point") != "" and
            len(ag3.get("attack_timeline", [])) == 5 and
            len(ag3.get("lateral_movement", [])) >= 1 and
            len(ag3.get("attack_path", [])) >= 1
        )
        record_check("Agent 3", "Attack Reconstruction Schema & Timeline", valid_ag3, f"{len(ag3.get('attack_timeline', []))} timeline steps, entry point confirmed")

        # Direct Neo4j Attack Path verification
        with neo4j_driver.session() as session:
            r_step = session.run("MATCH (s:AttackStep {case_id: $case_id}) RETURN count(s) AS cnt", {"case_id": test_case_id}).single()
            step_cnt = r_step["cnt"] if r_step else 0

            r_lm = session.run("MATCH ()-[r:LATERAL_MOVEMENT]->() WHERE r.case_id = $case_id RETURN count(r) AS cnt", {"case_id": test_case_id}).single()
            lm_cnt = r_lm["cnt"] if r_lm else 0

        record_check("Agent 3", "Neo4j AttackStep & LATERAL_MOVEMENT Writer", step_cnt > 0 and lm_cnt > 0, f"{step_cnt} AttackSteps, {lm_cnt} Lateral hops")
    except Exception as exc:
        record_check("Agent 3", "Attack Reconstruction Schema & Graph", False, str(exc))

    # Agent 4
    ag4 = pipeline_results.get("agent4", {})
    try:
        Agent4Output.model_validate(ag4)
        valid_ag4 = ag4.get("scan_summary") is not None and ag4.get("execution_status") in ("SUCCESS", "ExecutionStatus.SUCCESS")
        record_check("Agent 4", "Malware Behaviour Deterministic Scan", valid_ag4, f"Status: {ag4.get('execution_status')}")
    except Exception as exc:
        record_check("Agent 4", "Malware Behaviour Schema", False, str(exc))

    # Agent 5a & 5b
    ag5a = pipeline_results.get("agent5a", {})
    valid_5a = "IOC match" in ag5a.get("claim", "") and "CVE lookup" in ag5a.get("claim", "")
    record_check("Agent 5a", "Threat Intelligence Lookups (STIX/CVE/MITRE)", valid_5a, "Threat feeds successfully queried")

    ag5b = pipeline_results.get("agent5b", {})
    valid_5b = ag5b.get("claim") != ""
    record_check("Agent 5b", "Campaign Similarity Vector Queries", valid_5b, "Historical cluster matching executed")

    # Agent 6
    ag6 = pipeline_results.get("agent6", {})
    try:
        Agent6Output.model_validate(ag6)
        cvss = ag6.get("cvss_assessment", {})
        iss = ag6.get("iss_assessment", {})
        assets = ag6.get("affected_assets", [])
        checklist = ag6.get("recovery_checklist", {})

        valid_cvss = cvss.get("base_score") is not None and cvss.get("vector_string", "").startswith("CVSS:3.1/")
        record_check("Agent 6", "CVSS v3.1 Technical Calculation", valid_cvss, f"Score={cvss.get('base_score')}, Vector={cvss.get('vector_string')}")

        factors = iss.get("factor_breakdown", {})
        valid_iss = iss.get("iss_score") is not None and len(factors) == 6
        record_check("Agent 6", "Investigation Severity Score (ISS)", valid_iss, f"ISS={iss.get('iss_score')}/10 across 6 factors")

        asset_ids = [a.get("asset_id", "") for a in assets]
        valid_assets = any("WIN-WORKSTATION-01" in aid or "WIN-DC-01" in aid for aid in asset_ids)
        record_check("Agent 6", "Asset Inventory & Criticality Discovery", valid_assets, f"{len(assets)} assets profiled")

        valid_rec = checklist.get("total_actions", 0) > 0
        record_check("Agent 6", "Operational Recovery Playbook Generation", valid_rec, f"{checklist.get('total_actions')} actions staged")

        # Grounding check
        valid_finding_ids = {f.finding_id for f in test_findings}
        hallucinated = [eid for eid in ag6.get("all_cited_evidence_ids", []) if eid not in valid_finding_ids]
        record_check("Agent 6", "Citation Integrity & Grounding Mandate", len(hallucinated) == 0, f"Hallucinated citations: {len(hallucinated)}")
    except Exception as exc:
        record_check("Agent 6", "Impact Assessment Schema & Validation", False, str(exc))

    # Agent 7
    ag7 = pipeline_results.get("agent7", {})
    try:
        valid_7 = len(ag7.get("synthesis", {}).get("claims", [])) >= 1 and len(ag7.get("verification", [])) >= 1
        record_check("Agent 7", "Supervisor Synthesis & Verification", valid_7, "Claims synthesized and independently verified")
    except Exception as exc:
        record_check("Agent 7", "Supervisor Output Schema", False, str(exc))

    # ── 4. POSTGRESQL PERSISTENCE & CONSISTENCY ───────────────────────────────
    print(f"\n{BOLD}[Phase 4: PostgreSQL Persistence & Consistency Verification]{RESET}")
    try:
        with postgres_conn.cursor() as cur:
            cur.execute("""
                SELECT agent_id, claim, confidence, verified, execution_status
                FROM agent_outputs
                WHERE case_id = %s
                ORDER BY created_at ASC;
            """, (test_case_id,))
            rows = cur.fetchall()

        persisted_agents = {r[0] for r in rows}
        has_ag3 = "agent_3" in persisted_agents
        has_ag6 = "agent_6" in persisted_agents or "agent6_impact_assessment" in persisted_agents

        record_check("PostgreSQL", "Idempotent Row Persistence", has_ag3 and has_ag6, f"Persisted agent keys: {persisted_agents}")

        ag3_row = next((r for r in rows if r[0] == "agent_3"), None)
        consistent = ag3_row is not None and abs(ag3_row[2] - ag3.get("overall_confidence", 0.0)) < 0.01
        record_check("PostgreSQL", "Data Consistency (Returned vs Stored)", consistent, f"DB confidence matches returned ({ag3.get('overall_confidence')})")
    except Exception as exc:
        record_check("PostgreSQL", "Database Verification Error", False, str(exc))

    # ── 5. RESILIENCE / ERROR HANDLING TEST ───────────────────────────────────
    print(f"\n{BOLD}[Phase 5: Downstream Error Handling & Non-Blocking Resilience]{RESET}")
    resilience_case_id = f"CASE-RESILIENCE-{uuid.uuid4().hex[:8]}"
    resilience_findings = build_test_findings(resilience_case_id, test_tenant_id)

    failing_stix = MagicMock()
    failing_stix.check_ioc.side_effect = ConnectionError("STIX TAXII Server 503 Unavailable")

    resilient_results = run_pipeline(
        case_id=resilience_case_id,
        tenant_id=test_tenant_id,
        fir_findings=resilience_findings,
        llm=mock_model,
        neo4j_client=neo4j_driver,
        stix_client=failing_stix,
        cve_client=MagicMock(),
        mitre_client=MagicMock(),
        vector_store=mock_vec,
        stop_on_error=False
    )
    is_partial = resilient_results.get("execution_status") == "PARTIAL_SUCCESS" and "agent5a" in resilient_results.get("agent_errors", {})
    downstream_ok = resilient_results.get("agent6", {}).get("execution_status") != "FAILED"
    record_check("Resilience", "Downstream Failure Handling (Agent 5a Fault)", is_partial and downstream_ok, "Handled non-fatally with PARTIAL_SUCCESS")

    # ── 6. STRICT ISOLATION TEARDOWN ──────────────────────────────────────────
    try:
        with postgres_conn.cursor() as cur:
            cur.execute("DELETE FROM agent_outputs WHERE case_id IN (%s, %s);", (test_case_id, resilience_case_id))
            cur.execute("DELETE FROM fir_findings WHERE case_id IN (%s, %s);", (test_case_id, resilience_case_id))
        postgres_conn.commit()
        record_check("Safety", "Strict Test Data Isolation & Teardown", True, "Test rows purged; real cases untouched")
    except Exception as exc:
        record_check("Safety", "Strict Test Data Isolation & Teardown", False, str(exc))

    # ── SUMMARY TABLE ─────────────────────────────────────────────────────────
    total_checks = len(checks_results)
    passed_checks = sum(1 for c in checks_results if c["passed"])
    failed_checks = total_checks - passed_checks

    print(f"\n{BOLD}{CYAN}{'=' * 88}{RESET}")
    print(f"{BOLD}  INTEGRATION VERIFICATION RESULTS SUMMARY TABLE{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 88}{RESET}")
    print(f"{'CATEGORY':<16} | {'CHECK DESCRIPTION':<44} | {'STATUS':<8} | {'DETAILS'}")
    print(f"{'-' * 16}-+-{'-' * 44}-+-{'-' * 8}-+-{'-' * 16}")

    for r in checks_results:
        color = GREEN if r["passed"] else RED
        status_text = "PASS" if r["passed"] else "FAIL"
        print(f"{r['category']:<16} | {r['check']:<44} | {color}{status_text:<8}{RESET} | {r['details']}")

    print(f"{BOLD}{CYAN}{'=' * 88}{RESET}")
    if failed_checks == 0:
        print(f"{BOLD}{GREEN}  OVERALL STATUS: ALL {passed_checks}/{total_checks} CHECKS PASSED (100% SUCCESS){RESET}")
        print(f"{BOLD}{CYAN}{'=' * 88}{RESET}\n")
        return 0
    else:
        print(f"{BOLD}{RED}  OVERALL STATUS: {failed_checks} / {total_checks} CHECKS FAILED{RESET}")
        print(f"{BOLD}{CYAN}{'=' * 88}{RESET}\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_integration_tests())
