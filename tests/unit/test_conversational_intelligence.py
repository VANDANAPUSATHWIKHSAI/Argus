import time
import pytest
from forensic_analysis.conversational_assistant import (
    ConversationalInvestigationEngine,
    IntentCategory,
    normalize_query,
)
from forensic_analysis.investigation_context import CaseInvestigationContext


class TestConversationalIntelligence:
    def setup_method(self):
        self.context = CaseInvestigationContext("ARGUS_39", "default")
        self.context.evidence_records = [
            {"evidence_id": "EV-001", "filename": "NTUSER.DAT", "sha256_hash": "a" * 64},
            {"evidence_id": "EV-002", "filename": "SYSTEM", "sha256_hash": "b" * 64},
        ]
        self.context.findings = [
            {
                "finding_id": "F-001",
                "fact": "calc.exe executed from RecentDocs MRUListEx index",
                "confidence": 0.88,
                "severity": "low",
                "layer": "registry",
                "evidence_reference": ["EV-001"],
            },
            {
                "finding_id": "F-002",
                "fact": "Service persistence established under HKLM\\System\\CurrentControlSet\\Services\\EvilSvc",
                "confidence": 0.94,
                "severity": "high",
                "layer": "registry",
                "evidence_reference": ["EV-002"],
            },
        ]
        self.context.iss_score = 4.5
        self.context.iss_severity = "Medium"
        self.engine = ConversationalInvestigationEngine(context=self.context)

    def test_typo_normalization(self):
        assert normalize_query("heelo world") == "hello world"
        assert normalize_query("wat happend to the evidenc frm the host") == "what happened to the evidence from the host"
        assert normalize_query("is it serios bcoz of the atack") == "is it serious because of the attack"
        # Preserve technical tokens
        assert normalize_query("check FIR-102 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "check FIR-102 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_five_intent_categories(self):
        # Category A: Casual / Meta
        assert self.engine.classify_intent("hello") == IntentCategory.CASUAL
        assert self.engine.classify_intent("who are you") == IntentCategory.CASUAL
        assert self.engine.classify_intent("what can you do") == IntentCategory.CASUAL
        assert self.engine.classify_intent("thank you") == IntentCategory.CASUAL

        # Category B: General Cybersecurity Knowledge
        assert self.engine.classify_intent("what is mimikatz") == IntentCategory.GENERAL_KNOWLEDGE
        assert self.engine.classify_intent("how does pass-the-hash work") == IntentCategory.GENERAL_KNOWLEDGE
        assert self.engine.classify_intent("explain t1059") == IntentCategory.GENERAL_KNOWLEDGE
        assert self.engine.classify_intent("what is kerberoasting") == IntentCategory.GENERAL_KNOWLEDGE

        # Category C: Case-Specific
        assert self.engine.classify_intent("what happened in this case") == IntentCategory.CASE_SPECIFIC
        assert self.engine.classify_intent("show evidence files") == IntentCategory.CASE_SPECIFIC
        assert self.engine.classify_intent("what is the iss score") == IntentCategory.CASE_SPECIFIC

        # Category D: Contextual Follow-up
        assert self.engine.classify_intent("what about the second one") == IntentCategory.FOLLOW_UP
        assert self.engine.classify_intent("is it serious") == IntentCategory.FOLLOW_UP
        assert self.engine.classify_intent("explain this") == IntentCategory.FOLLOW_UP

        # Category E: Complex Reasoning
        assert self.engine.classify_intent("could this be an insider") == IntentCategory.COMPLEX_REASONING
        assert self.engine.classify_intent("what if the timestamp was spoofed") == IntentCategory.COMPLEX_REASONING

    def test_fast_path_latency_under_5ms(self):
        queries = ["heelo", "who are you", "what can you do", "thanks", "what is mimikatz", "what is t1059"]
        for q in queries:
            t0 = time.perf_counter()
            resp, meta = self.engine.answer_fast_path(q)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            assert resp is not None
            assert elapsed_ms < 10.0, f"Query '{q}' took {elapsed_ms:.2f}ms, expected < 10ms"
            assert meta.get("execution_mode") == "RETRIEVAL_ONLY"

    def test_direct_answer_first_sentence_for_followups(self):
        prefix = "[ARGUS Grounded Retrieval Mode — Local Qwen3:8B Unavailable]\n\n"
        # Second finding follow-up
        resp2 = self.engine.answer_query("what about the second one").replace(prefix, "")
        assert resp2.startswith("The second finding is")
        assert "EvilSvc" in resp2
        assert "HIGH" in resp2

        # First finding follow-up
        resp1 = self.engine.answer_query("what about the first one").replace(prefix, "")
        assert resp1.startswith("The first finding is")
        assert "calc.exe" in resp1

        # Severity inquiry
        resp_sev = self.engine.answer_query("is it serious").replace(prefix, "")
        assert resp_sev.startswith("Yes, serious security findings were detected")
        assert "4.5/10" in resp_sev

    def test_complex_forensic_reasoning_hypothesis(self):
        prefix = "[ARGUS Grounded Retrieval Mode — Local Qwen3:8B Unavailable]\n\n"
        resp_insider = self.engine.answer_query("could this be an insider").replace(prefix, "")
        assert resp_insider.startswith("An insider threat hypothesis cannot be confirmed or ruled out")
        assert "logon telemetry" in resp_insider

        resp_spoof = self.engine.answer_query("what if the timestamp was spoofed").replace(prefix, "")
        assert resp_spoof.startswith("No evidence of timestamp spoofing (timestomping) was observed")
        assert "$STANDARD_INFORMATION" in resp_spoof
