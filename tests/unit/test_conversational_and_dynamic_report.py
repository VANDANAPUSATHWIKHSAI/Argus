"""
Unit & Regression Tests: Conversational Assistant & Dynamic Case-Dependent Reporting
==================================================================================
Tests:
  1. Conversational Engine:
     - Natural language queries with typos ("heelo", "how attck happend", "where did attacker entr")
     - Multi-turn conversational memory and pronoun resolution ("what did they do next?")
     - Epistemic grounding & negative evidence semantics (does not declare clean, separates uncollected)
     - Safe retrieval fallback when Ollama is unavailable
  2. Dynamic Report Generator:
     - Case ARGUS_38: Registry artifacts, RecentDocs, ISS 2.2, NO fake C2 beaconing (know.mom-nower.com)
     - Case ARGUS_06: PCAP / Suricata alerts, NO fake know.mom-nower.com
     - Case Empty / Baseline: Clear statement of no anomalies identified, never declares whole system clean
     - Timestamp fidelity: Chain of custody vs event timestamps
     - Dynamic SVG graph generation: Data-driven visual_nodes and visual_edges
"""

import pytest
import os
from unittest.mock import patch, MagicMock

from forensic_analysis.investigation_context import CaseInvestigationContext
from forensic_analysis.conversational_assistant import ConversationalInvestigationEngine
from report_generation.generator import ReportGenerator


class TestConversationalEngine:
    """Tests natural language understanding, multi-turn dialogue, ambiguity, and forensic semantics."""

    def test_conversational_greeting_and_typo(self):
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [{"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "abc"}]
        ctx.modalities = {"REGISTRY"}
        engine = ConversationalInvestigationEngine(context=ctx)

        resp = engine.answer_query(
            query="heelo",
            history=[]
        )
        assert resp is not None
        assert len(resp) > 0
        # Must not dump a hardcoded C2 containment plan for a simple greeting
        assert "know.mom-nower.com" not in resp
        assert "185.220.101.5" not in resp

    def test_conversational_typo_intent_recognition(self):
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [
            {"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "abc"},
            {"evidence_id": "EVID-02", "filename": "NTUSER.DAT", "sha256_hash": "def"},
        ]
        ctx.findings = [
            {
                "finding_id": "F-001",
                "fact": "Recent document interaction recorded in RecentDocs MRU: document 'calc.exe'",
                "confidence": 0.85,
                "severity": "low",
                "evidence_reference": ["NTUSER.DAT"],
            }
        ]
        ctx.modalities = {"REGISTRY"}
        ctx._build_chronological_timeline()
        ctx._compute_iss_impact()
        engine = ConversationalInvestigationEngine(context=ctx)

        # Query with typos and informal language
        resp = engine.answer_query(
            query="how attck happend? did they entr inside?",
            history=[]
        )
        assert resp is not None
        # Must reference actual evidence or clearly state what was examined
        assert "know.mom-nower.com" not in resp

    def test_multi_turn_history_formatting(self):
        engine = ConversationalInvestigationEngine()
        history = [
            {"role": "user", "content": "What files were examined?"},
            {"role": "assistant", "content": "SYSTEM and NTUSER.DAT registry hives were examined."},
        ]
        formatted = engine._format_conversation_history(history)
        assert "What files were examined?" in formatted
        assert "SYSTEM and NTUSER.DAT" in formatted

    def test_multi_turn_pronoun_resolution(self):
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [
            {"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "9301e90605560113", "status": "stored"},
            {"evidence_id": "EVID-02", "filename": "NTUSER.DAT", "sha256_hash": "4513dcd763bf88c2", "status": "stored"}
        ]
        ctx.modalities = {"REGISTRY"}
        engine = ConversationalInvestigationEngine(context=ctx)

        # Turn 1: user asks what was examined, assistant answers
        history = [
            {"role": "user", "content": "What files were uploaded?"},
            {"role": "assistant", "content": "Evidence Ingested for Case ARGUS_38: SYSTEM, NTUSER.DAT."}
        ]
        # Turn 2: user asks how "it" was verified
        resp = engine.answer_query(query="how was it verified?", history=history)
        assert resp is not None
        assert "SHA-256" in resp or "verified" in resp.lower()
        assert "SYSTEM" in resp or "NTUSER.DAT" in resp

    def test_ambiguous_question_handling(self):
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [{"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "abc"}]
        ctx.findings = [{"finding_id": "F-01", "fact": "Registry cell analyzed", "confidence": 0.9, "severity": "low"}]
        ctx.modalities = {"REGISTRY"}
        ctx._compute_iss_impact()
        engine = ConversationalInvestigationEngine(context=ctx)

        # Ambiguous 1-2 word question
        resp = engine.answer_query(query="explain", history=[])
        assert resp is not None
        # Should ask clarifying question or present candidate dimensions
        assert "clarify" in resp.lower() or "which aspect" in resp.lower() or "Case ARGUS_38" in resp

    def test_why_reasoning_explanation(self):
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [{"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "abc"}]
        ctx.findings = [
            {"finding_id": "F-01", "fact": "User document access tracking structure identified in RecentDocs MRU", "confidence": 0.95, "severity": "informational", "layer": "REGISTRY"}
        ]
        ctx.modalities = {"REGISTRY"}
        ctx._compute_iss_impact()
        engine = ConversationalInvestigationEngine(context=ctx)

        # Analyst asks "why did you conclude..."
        resp = engine.answer_query(query="Why did you conclude this was informational?", history=[])
        assert resp is not None
        assert "Evidentiary Basis" in resp or "grounded" in resp.lower() or "RecentDocs" in resp
        assert "SYSTEM" in resp

    def test_contradictory_evidence_inquiry(self):
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [{"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "abc"}]
        ctx.modalities = {"REGISTRY"}
        engine = ConversationalInvestigationEngine(context=ctx)

        resp = engine.answer_query(query="Is there any contradictory evidence or conflict?", history=[])
        assert resp is not None
        assert "Consistency" in resp or "Scope" in resp or "uncollected" in resp

    def test_dynamic_variation_when_case_changes(self):
        ctx1 = CaseInvestigationContext("ARGUS_38", "default")
        ctx1.evidence_records = [{"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "abc"}]
        ctx1.findings = [{"finding_id": "F-01", "fact": "Registry key modified", "confidence": 0.8, "severity": "low"}]
        ctx1.modalities = {"REGISTRY"}
        engine1 = ConversationalInvestigationEngine(context=ctx1)
        resp1 = engine1.answer_query(query="what files are in this case?", history=[])

        ctx2 = CaseInvestigationContext("ARGUS_06", "default")
        ctx2.evidence_records = [{"evidence_id": "EVID-02", "filename": "network_traffic.pcap", "sha256_hash": "xyz"}]
        ctx2.findings = [{"finding_id": "F-02", "fact": "DNS query to external host", "confidence": 0.9, "severity": "medium"}]
        ctx2.modalities = {"NETWORK"}
        engine2 = ConversationalInvestigationEngine(context=ctx2)
        resp2 = engine2.answer_query(query="what files are in this case?", history=[])

        assert "SYSTEM" in resp1
        assert "network_traffic.pcap" in resp2
        assert "network_traffic.pcap" not in resp1

    def test_retrieval_fallback_when_ollama_fails(self):
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [{"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "abc"}]
        ctx.findings = [{"finding_id": "F-01", "fact": "Registry cell inspected", "confidence": 0.9, "severity": "low"}]
        ctx.modalities = {"REGISTRY"}
        ctx._compute_iss_impact()
        engine = ConversationalInvestigationEngine(context=ctx)

        # Force Ollama generation to fail by mocking OllamaWrapper
        with patch("forensic_analysis.conversational_assistant.OllamaWrapper.generate", side_effect=Exception("Connection refused")):
            resp = engine.answer_query(
                query="give me proofs of what happened",
                history=[]
            )
            assert resp is not None
            # Must return a clear, honest grounded response, not hallucinated inferences
            assert "Proof" in resp or "SHA-256" in resp or "SYSTEM" in resp
            assert "know.mom-nower.com" not in resp


class TestDynamicReportGeneration:
    """Tests dynamic, case-dependent report generation."""

    def test_argus_38_registry_report_grounding(self):
        gen = ReportGenerator()
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [
            {"evidence_id": "EVID-01", "filename": "SYSTEM", "sha256_hash": "9301e90605560113", "status": "stored"},
            {"evidence_id": "EVID-02", "filename": "NTUSER.DAT", "sha256_hash": "4513dcd763bf88c2", "status": "stored"},
            {"evidence_id": "EVID-03", "filename": "SOFTWARE", "sha256_hash": "afbb75e6b656346e", "status": "stored"},
        ]
        ctx.findings = [
            {
                "finding_id": "F-001",
                "fact": "Recent document interaction recorded in RecentDocs MRU: document 'calc.exe'",
                "confidence": 0.85,
                "severity": "low",
                "evidence_reference": ["NTUSER.DAT"],
            }
        ]
        ctx.modalities = {"REGISTRY"}
        ctx._build_chronological_timeline()
        ctx._compute_iss_impact()

        report_data = {
            "case_id": "ARGUS_38",
            "tenant_id": "default",
            "evidence_files": ctx.evidence_records,
            "findings": ctx.findings,
        }
        context = gen._prepare_context(report_data)

        # 1. Glance
        glance = context["glance"]
        assert "SYSTEM" in glance["summary_narrative"]
        assert "Windows Registry" in glance["attack_type"]
        assert glance["scores"]["iss"]["score"] > 0
        assert "No Binaries in Evidence" in glance["scores"]["malware"]["label"]

        # 2. Strict Negative Verification: Zero fake C2 indicators
        html_out = gen.generate(report_data, format="html")
        assert "know.mom-nower.com" not in html_out
        assert "185.220.101.5" not in html_out
        assert "42 DGA Queries" not in html_out

        # 3. Dynamic SVG visual nodes exist
        assert "visual_nodes" in context["graph_metrics"]
        assert len(context["graph_metrics"]["visual_nodes"]) >= 4

    def test_argus_06_pcap_report_grounding(self):
        gen = ReportGenerator()
        ctx = CaseInvestigationContext("ARGUS_06", "default")
        ctx.evidence_records = [
            {"evidence_id": "EVID-01", "filename": "2026-09-11-traffic-analysis-exercise.pcap", "sha256_hash": "21bb800849459709", "status": "stored"}
        ]
        ctx.findings = [
            {
                "finding_id": "F-101",
                "fact": "Suricata IDS Alert: 'ET INFO Observed DNS Query to .cfd TLD'",
                "confidence": 0.9,
                "severity": "medium",
                "evidence_reference": ["2026-09-11-traffic-analysis-exercise.pcap"],
            },
            {
                "finding_id": "F-102",
                "fact": "Suricata IDS Alert: 'SURICATA STREAM excessive retransmissions'",
                "confidence": 0.9,
                "severity": "low",
                "evidence_reference": ["2026-09-11-traffic-analysis-exercise.pcap"],
            }
        ]
        ctx.modalities = {"NETWORK"}
        ctx._build_chronological_timeline()
        ctx._compute_iss_impact()

        report_data = {
            "case_id": "ARGUS_06",
            "tenant_id": "default",
            "evidence_files": ctx.evidence_records,
            "findings": ctx.findings,
        }
        context = gen._prepare_context(report_data)

        # Must reflect real PCAP evidence and Suricata detections
        glance = context["glance"]
        assert "traffic-analysis-exercise.pcap" in glance["summary_narrative"]
        assert "Network" in glance["attack_type"]

        html_out = gen.generate(report_data, format="html")
        # Must NOT inject fake know.mom-nower.com domain
        assert "know.mom-nower.com" not in html_out
        # Must reflect actual .cfd alert from real finding
        assert ".cfd" in html_out or "Suricata" in html_out

    def test_empty_case_negative_evidence_semantics(self):
        gen = ReportGenerator()
        ctx = CaseInvestigationContext("ARGUS_EMPTY", "default")
        ctx.evidence_records = [
            {"evidence_id": "EVID-01", "filename": "clean_container.raw", "sha256_hash": "1122334455667788", "status": "stored"}
        ]
        ctx.findings = []
        ctx.modalities = {"GENERIC_CONTAINER"}
        ctx._build_chronological_timeline()
        ctx._compute_iss_impact()

        report_data = {
            "case_id": "ARGUS_EMPTY",
            "tenant_id": "default",
            "evidence_files": ctx.evidence_records,
            "findings": [],
        }
        context = gen._prepare_context(report_data)

        # 1. Cluster must clearly state no malicious findings identified
        clusters = context["findings_clusters"]
        assert len(clusters) == 1
        assert "No Malicious Findings Identified" in clusters[0]["title"]

        # 2. Must NOT claim entire system is clean
        html_out = gen.generate(report_data, format="html")
        assert "know.mom-nower.com" not in html_out
        assert "Zero anomalous or malicious indicators" in html_out
        # Negative evidence boundary: distinguishes uncollected from clean
        assert "cannot be definitively declared clean" in html_out or "uncollected" in html_out

    def test_no_confirmed_malware_semantics(self):
        gen = ReportGenerator()
        ctx = CaseInvestigationContext("ARGUS_NO_MALWARE", "default")
        ctx.evidence_records = [
            {"evidence_id": "EVID-01", "filename": "event_logs.evtx", "sha256_hash": "aabbccdd11223344", "status": "stored"}
        ]
        ctx.findings = [
            {"finding_id": "F-01", "fact": "Event ID 4624 successful logon for user Administrator", "confidence": 0.95, "severity": "informational"}
        ]
        ctx.modalities = {"EVENT_LOGS"}
        ctx._build_chronological_timeline()
        ctx._compute_iss_impact()

        report_data = {
            "case_id": "ARGUS_NO_MALWARE",
            "tenant_id": "default",
            "evidence_files": ctx.evidence_records,
            "findings": ctx.findings,
        }
        context = gen._prepare_context(report_data)
        mal = context["malware_analysis"]

        # Must report binary not submitted, 0 YARA rules executed
        assert mal["yara_rules_executed"] == 0
        assert "NO MALWARE BINARIES SUBMITTED" in mal["status"]
        assert "N/A" in mal["yara_matches"]

        html_out = gen.generate(report_data, format="html")
        # Must not fabricate a malware family name
        assert "Cobalt Strike" not in html_out
        assert "Emotet" not in html_out

    def test_unestablished_initial_access_and_exfiltration(self):
        gen = ReportGenerator()
        ctx = CaseInvestigationContext("ARGUS_ISOLATED", "default")
        ctx.evidence_records = [
            {"evidence_id": "EVID-01", "filename": "NTUSER.DAT", "sha256_hash": "4513dcd763bf88c2", "status": "stored"}
        ]
        ctx.findings = [
            {"finding_id": "F-01", "fact": "User document access tracking structure identified in RecentDocs MRU", "confidence": 0.9, "severity": "informational"}
        ]
        ctx.modalities = {"REGISTRY"}
        ctx._build_chronological_timeline()
        ctx._compute_iss_impact()

        report_data = {
            "case_id": "ARGUS_ISOLATED",
            "tenant_id": "default",
            "evidence_files": ctx.evidence_records,
            "findings": ctx.findings,
        }
        context = gen._prepare_context(report_data)

        # Gaps must indicate attribution / uncollected telemetry
        gaps = context["evidence_gaps"]
        assert any("Attribution" in g["domain"] or "Uncollected" in g["status"] for g in gaps)

        # Hypotheses must acknowledge unconfirmed execution/lateral pivot
        unconfirmed = context["unconfirmed_stages"]
        assert len(unconfirmed) > 0
        assert any("Uncollected" in u["stage"] or "Hypothesis" in u["stage"] for u in unconfirmed)

    def test_adaptive_sizing_few_vs_many_findings(self):
        gen = ReportGenerator()

        # Few findings
        report_small = {
            "case_id": "ARGUS_SMALL",
            "tenant_id": "default",
            "evidence_files": [{"evidence_id": "E1", "filename": "SYSTEM", "sha256_hash": "111"}],
            "findings": [{"finding_id": "F1", "fact": "Single registry key read", "confidence": 0.8, "severity": "informational", "layer": "REGISTRY"}],
        }
        ctx_small = gen._prepare_context(report_small)
        assert len(ctx_small["findings_clusters"]) == 1

        # Many findings across multiple layers
        many_findings = []
        for i in range(25):
            many_findings.append({"finding_id": f"FR{i}", "fact": f"Registry key modification {i}", "confidence": 0.9, "severity": "low", "layer": "REGISTRY"})
            many_findings.append({"finding_id": f"FN{i}", "fact": f"DNS request query {i}", "confidence": 0.85, "severity": "medium", "layer": "NETWORK"})
            many_findings.append({"finding_id": f"FE{i}", "fact": f"Event ID 4688 process execution {i}", "confidence": 0.95, "severity": "low", "layer": "EVENT_LOGS"})

        report_large = {
            "case_id": "ARGUS_LARGE",
            "tenant_id": "default",
            "evidence_files": [
                {"evidence_id": "E1", "filename": "SYSTEM", "sha256_hash": "111"},
                {"evidence_id": "E2", "filename": "traffic.pcap", "sha256_hash": "222"},
                {"evidence_id": "E3", "filename": "security.evtx", "sha256_hash": "333"},
            ],
            "findings": many_findings,
        }
        ctx_large = gen._prepare_context(report_large)
        # Should cluster across registry, network, and event log modalities
        assert len(ctx_large["findings_clusters"]) >= 3
        assert ctx_large["glance"]["correlated_events_count"] == 75

    def test_mrulistex_forensic_semantics_in_context_and_report(self):
        # Verify MRUListEx index array is never reported as a document filename
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        raw_fact = "Recent document interaction recorded in RecentDocs MRU: document 'MRUListEx'"
        cleaned_fact = ctx._clean_fact_semantics(raw_fact)
        assert "document 'mrulistex'" not in cleaned_fact.lower()
        assert "MRUListEx ordering sequence index" in cleaned_fact

        # Verify ReportGenerator output doesn't claim MRUListEx is a document
        gen = ReportGenerator()
        report_data = {
            "case_id": "ARGUS_38",
            "tenant_id": "default",
            "evidence_files": [{"evidence_id": "E1", "filename": "NTUSER.DAT", "sha256_hash": "111"}],
            "findings": [{"finding_id": "F1", "fact": cleaned_fact, "confidence": 0.95, "severity": "informational"}],
        }
        html_out = gen.generate(report_data, format="html")
        assert "document 'MRUListEx'" not in html_out
        assert "document \"MRUListEx\"" not in html_out

    def test_tenant_and_case_isolation(self):
        gen = ReportGenerator()
        report_a = {
            "case_id": "CASE_ALPHA",
            "tenant_id": "tenant_a",
            "evidence_files": [{"evidence_id": "E_A", "filename": "alpha_evidence.raw", "sha256_hash": "aaa"}],
            "findings": [{"finding_id": "FA", "fact": "Alpha unique observable fact", "confidence": 0.9, "severity": "low"}],
        }
        report_b = {
            "case_id": "CASE_BETA",
            "tenant_id": "tenant_b",
            "evidence_files": [{"evidence_id": "E_B", "filename": "beta_evidence.raw", "sha256_hash": "bbb"}],
            "findings": [{"finding_id": "FB", "fact": "Beta unique observable fact", "confidence": 0.9, "severity": "low"}],
        }
        html_a = gen.generate(report_a, format="html")
        html_b = gen.generate(report_b, format="html")

        assert "alpha_evidence.raw" in html_a
        assert "beta_evidence.raw" not in html_a
        assert "Beta unique observable fact" not in html_a

        assert "beta_evidence.raw" in html_b
        assert "alpha_evidence.raw" not in html_b
        assert "Alpha unique observable fact" not in html_b

    def test_qwen3_8b_model_propagation(self):
        """Verify Qwen3:8B model tag is configured and propagated without substitute remapping."""
        from config.settings import settings
        from models.llm import OllamaWrapper

        assert settings.llm_model_name == "qwen3:8b"
        wrapper = OllamaWrapper(model_name="qwen3:8b", base_url="http://127.0.0.1:11434", allow_mock=False)
        assert wrapper.model_name == "qwen3:8b"
        assert wrapper.allow_mock is False
        assert wrapper.base_url == "http://127.0.0.1:11434"

    def test_ollama_unavailable_grounded_retrieval_mode(self):
        """Verify that when Ollama is unavailable, the engine returns explicitly labelled retrieval mode."""
        from config.settings import settings
        orig_url = settings.ollama_base_url
        try:
            settings.ollama_base_url = "http://127.0.0.1:59998"
            ctx = CaseInvestigationContext("ARGUS_38", "default")
            ctx.evidence_records = [{"evidence_id": "E1", "filename": "NTUSER.DAT", "sha256_hash": "aaa"}]
            ctx.findings = [{"finding_id": "F1", "fact": "calc.exe observed in RecentDocs", "confidence": 0.85, "severity": "low"}]
            ctx.modalities = {"REGISTRY"}
            engine = ConversationalInvestigationEngine(context=ctx)

            resp = engine.answer_query("What was the suspicious file?")
            assert "[ARGUS Grounded Retrieval Mode — Local Qwen3:8B Unavailable]" in resp
            # Must contain actual case evidence, not synthetic mock JSON
            assert "NTUSER.DAT" in resp or "calc.exe" in resp or "REGISTRY" in resp
            assert '{"executive_summary"' not in resp
        finally:
            settings.ollama_base_url = orig_url

    def test_finding_revision_repository_append_only_and_isolation(self):
        """Verify append-only finding revisions, tenant/case isolation, and idempotency."""
        import uuid
        from fir.revision_schemas import FindingCorrectionRecord, CorrectionStatus
        from fir.finding_revision_repository import FindingRevisionRepository

        repo = FindingRevisionRepository()
        rec = FindingCorrectionRecord(
            revision_id=str(uuid.uuid4()),
            original_finding_id="f-test-001",
            case_id="CASE_TEST",
            tenant_id="tenant_alpha",
            original_wording="Raw index array 0, 1, 2",
            corrected_interpretation="Explorer MRU order corrected",
            correction_reason="Parser upgrade v1.2",
            parser_analyzer_name="registry_parser",
            parser_version="v1.2.0",
            correction_status=CorrectionStatus.PROPOSED
        )

        r1, is_new1 = repo.record_correction(rec)
        assert is_new1 is True
        assert r1.revision_id == rec.revision_id

        # Idempotency: duplicate registration returns existing record
        r2, is_new2 = repo.record_correction(rec)
        assert is_new2 is False
        assert r2.revision_id == r1.revision_id

        # Read isolation
        found = repo.get_corrections_by_finding("f-test-001", "CASE_TEST", "tenant_alpha")
        assert len(found) >= 1

        isolated_tenant = repo.get_corrections_by_finding("f-test-001", "CASE_TEST", "tenant_beta")
        assert len(isolated_tenant) == 0

        isolated_case = repo.get_corrections_by_finding("f-test-001", "CASE_OTHER", "tenant_alpha")
        assert len(isolated_case) == 0

    def test_unexecuted_agents_marked_pending_pipeline_run(self):
        """Verify unexecuted agents are marked PENDING_PIPELINE_RUN, never SUCCESS."""
        gen = ReportGenerator()
        report_data = {
            "case_id": "ARGUS_MINIMAL",
            "tenant_id": "default",
            "evidence_files": [{"evidence_id": "E1", "filename": "test.raw", "sha256_hash": "111"}],
            "findings": [{"finding_id": "F1", "fact": "Raw byte string", "confidence": 0.5, "severity": "informational"}],
            "agent_outputs": {
                "agent1": {"status": "SUCCESS", "execution_time_seconds": 1.2},
                # Other agents not run
            }
        }
        panels = gen._build_agent_panels(report_data, [], {}, {})
        assert panels["agent1"]["status"] == "SUCCESS"
        assert panels["agent2"]["status"] == "PENDING_PIPELINE_RUN"
        assert panels["agent7"]["status"] == "PENDING_SUPERVISOR_REVIEW"

    def test_timeline_intake_timestamp_semantics(self):
        """Verify evidence acquisition timestamp is never presented as an attack event."""
        gen = ReportGenerator()
        ev_files = [
            {
                "evidence_id": "E1",
                "filename": "memdump.raw",
                "sha256_hash": "aaa",
                "upload_timestamp": "2026-11-10T10:00:00Z"
            }
        ]
        milestones = gen._build_milestone_timeline(raw_timeline=[], clusters=[], raw_evidence=ev_files)
        assert len(milestones) >= 1
        # Baseline intake must not be labeled as attack activity
        first = milestones[0]
        assert "Intake Baseline" in first["stage"] or "Evidence Acquisition" in first["stage"]
        assert "Not Incident Activity" in first["stage"]

    def test_attack_step_provenance_and_hypothesis_calibration(self):
        """Verify attack steps without confirmed exploit telemetry are classified as HYPOTHESIS."""
        from forensic_analysis.investigation_context import AttackStageProvenance
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.attack_steps = [
            {
                "id": "STEP-ARGUS_38-01",
                "step_number": 1,
                "stage": "Initial Access",
                "description": "Adversary activity detected: Initial Access",
                "confidence": 0.35,
                "provenance_type": AttackStageProvenance.HYPOTHESIS,
                "status": "UNCONFIRMED_HYPOTHESIS",
                "reasoning_basis": "Analytical kill-chain hypothesis inferred by Agent 3 from user activity metadata; unconfirmed due to absence of exploit or execution telemetry."
            }
        ]
        grounding = ctx.get_llm_grounding_block()
        assert "HYPOTHESIS — UNCONFIRMED HYPOTHESIS" in grounding
        assert "ZERO evidence of exploit" in grounding
        assert "Initial Access" in grounding

    def test_structured_query_response_metadata(self):
        """Verify QueryResponse exposes structured execution metadata fields."""
        from api.routes.query import QueryResponse
        resp = QueryResponse(
            response="Test verified forensic response",
            injection_flagged=False,
            injection_score=0.0,
            model_tag="qwen3:8b",
            execution_mode="LLM_GENERATED",
            retrieval_only=False,
            latency_ms=1250.5
        )
        assert resp.model_tag == "qwen3:8b"
        assert resp.execution_mode == "LLM_GENERATED"
        assert resp.retrieval_only is False
        assert resp.latency_ms == 1250.5

    def test_conversational_groundedness_recon_and_credential_safeguards(self):
        """Verify retrieval handler rejects ungrounded reconnaissance and credential harvesting speculation."""
        ctx = CaseInvestigationContext("ARGUS_38", "default")
        ctx.evidence_records = [{"evidence_id": "E1", "filename": "NTUSER.DAT", "sha256_hash": "aaa"}]
        ctx.findings = [{"finding_id": "F1", "fact": "calc.exe observed in RecentDocs", "confidence": 0.85, "severity": "informational"}]
        ctx.modalities = {"REGISTRY"}
        engine = ConversationalInvestigationEngine(context=ctx)

        resp_recon = engine._generate_retrieval_only_response("Was there reconnaissance?", history=[])
        assert "No evidence of reconnaissance was identified" in resp_recon

        resp_cred = engine._generate_retrieval_only_response("Was credential harvesting confirmed?", history=[])
        assert "No credential harvesting was identified or confirmed" in resp_cred

        resp_iss = engine._generate_retrieval_only_response("Why is the ISS score low?", history=[])
        assert "Investigation Impact Severity" in resp_iss
        assert "NOT proof that an attack stopped" in resp_iss

        resp_mru = engine._generate_retrieval_only_response("What does MRUListEx prove?", history=[])
        assert "MRUListEx" in resp_mru
        assert "ordering index" in resp_mru
        assert "NOT a document filename" in resp_mru

        resp_proof = engine._generate_retrieval_only_response("Show me the evidence for Initial Access and Execution.", history=[])
        assert "no concrete evidence" in resp_proof.lower()
        assert "unconfirmed analytical kill-chain hypotheses" in resp_proof

