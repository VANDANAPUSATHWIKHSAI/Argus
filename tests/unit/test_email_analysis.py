"""
Unit Test Suite — Email Analysis Engine
========================================
Comprehensive, self-contained unit tests covering all 6 sub-analyzers
(HeaderAnalyzer, AuthenticationAnalyzer, AttachmentAnalyzer, URLAnalyzer,
PhishingAnalyzer, MailboxTimelineAnalyzer), router dispatch, orchestrator batching,
UnifiedEvidenceStore persistence, FIR conversion, and AST security inspection.
"""

import os
import ast
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.schemas import CorrelationRecord
from forensic_analysis.router import route_fcr
from forensic_analysis.schemas import Finding, finding_to_fir
from forensic_analysis.unified_store import UnifiedEvidenceStore
from forensic_analysis.orchestrator import process_fcr_batch, ENGINE_REGISTRY
from forensic_analysis.email_analysis.email_engine import EmailAnalysisEngine
from forensic_analysis.email_analysis.header_analyzer import HeaderAnalyzer
from forensic_analysis.email_analysis.authentication_analyzer import AuthenticationAnalyzer
from forensic_analysis.email_analysis.attachment_analyzer import AttachmentAnalyzer
from forensic_analysis.email_analysis.url_analyzer import URLAnalyzer
from forensic_analysis.email_analysis.phishing_analyzer import PhishingAnalyzer
from forensic_analysis.email_analysis.mailbox_timeline_analyzer import MailboxTimelineAnalyzer
from fir.repository import FIRRepository
from fir.schemas import FIRFinding


def make_email_artifact(
    art_id: str,
    art_type: str = "email",
    case_id: str = "CASE-EMAIL-101",
    tenant_id: str = "default",
    source_tool: str = "python_email",
    raw_fields: dict = None,
    norm_fields: dict = None,
    ts: datetime = None
) -> Artifact:
    norm = NormalizedFields(**(norm_fields or {}))
    return Artifact(
        artifact_id=art_id,
        case_id=case_id,
        evidence_id="EVID-EMAIL-001",
        source_tool=source_tool,
        artifact_type=art_type,
        timestamp=ts or datetime.now(timezone.utc),
        normalized_fields=norm,
        raw_fields=raw_fields or {},
    )


def make_fcr(corr_id: str = "CORR-00100", art_ids: list[str] = None, case_id: str = "CASE-EMAIL-101") -> CorrelationRecord:
    effective_ids = list(art_ids or [])
    if len(effective_ids) < 2:
        effective_ids.append("A-DUMMY-PADDING-999")
    return CorrelationRecord(
        correlation_id=corr_id,
        case_id=case_id,
        artifact_ids=effective_ids,
        relationship_type=["temporal_proximity"],
        host="mail-server-1",
        source_count=len(effective_ids),
        distinct_artifact_types=len(effective_ids),
        confidence=0.85,
    )


# ── 1. Header Analyzer Tests ──────────────────────────────────────────────────

def test_header_analyzer_mismatches_and_anomalies():
    analyzer = HeaderAnalyzer()

    # Case A: From vs Reply-To mismatch
    art_mismatch = make_email_artifact("A-HDR-1", raw_fields={
        "sender": "CEO <ceo@company.com>",
        "reply_to": "attacker@evil.com",
        "return_path": "ceo@company.com",
        "headers": {
            "From": "CEO <ceo@company.com>",
            "Reply-To": "attacker@evil.com",
            "Return-Path": "ceo@company.com",
            "Message-ID": "<12345@company.com>"
        }
    })
    findings = analyzer.analyze(art_mismatch, ["CORR-00101"])
    assert any("From domain 'company.com' differs from Reply-To domain 'evil.com'" in f.fact for f in findings)
    assert any(f.layer == "email.header_analyzer" for f in findings)

    # Case B: Display Name impersonation email address mismatch
    art_disp = make_email_artifact("A-HDR-2", raw_fields={
        "headers": {
            "From": "\"PayPal Security <support@paypal.com>\" <hacker@malicious.ru>",
            "Message-ID": "<67890@malicious.ru>"
        }
    })
    findings_disp = analyzer.analyze(art_disp, ["CORR-00102"])
    assert any("Display name email address mismatch observed" in f.fact for f in findings_disp)

    # Case C: Message-ID structural anomaly
    art_msgid = make_email_artifact("A-HDR-3", raw_fields={
        "headers": {
            "From": "user@domain.com",
            "Message-ID": "invalid-message-id-format"
        }
    })
    findings_msgid = analyzer.analyze(art_msgid, ["CORR-00103"])
    assert any("Message-ID header structural anomaly observed" in f.fact for f in findings_msgid)


# ── 2. Authentication Analyzer Tests ──────────────────────────────────────────

def test_authentication_analyzer_failures():
    analyzer = AuthenticationAnalyzer()

    art_auth = make_email_artifact("A-AUTH-1", raw_fields={
        "authentication_results": "mx.google.com; spf=softfail (google.com: domain of evil.com does not designate 192.0.2.1 as permitted sender) smtp.mailfrom=evil.com; dkim=fail header.i=@evil.com; dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=company.com alignment=fail",
        "spf": "softfail",
        "dkim": "fail",
        "dmarc": "fail"
    })

    findings = analyzer.analyze(art_auth, ["CORR-AUTH-1"])
    facts = [f.fact for f in findings]

    assert any("SPF authentication softfail observed" in f for f in facts)
    assert any("DKIM authentication failure observed" in f for f in facts)
    assert any("DMARC authentication failure observed" in f for f in facts)
    assert any("DMARC domain alignment failure observed" in f for f in facts)


# ── 3. Attachment Analyzer Tests ──────────────────────────────────────────────

def test_attachment_analyzer_risk_indicators():
    analyzer = AttachmentAnalyzer()

    # Double extension & macro-enabled
    art_att = make_email_artifact("A-ATT-1", raw_fields={
        "attachments": [
            {"filename": "invoice.pdf.exe", "mimetype": "application/octet-stream", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {"filename": "financials.docm", "mimetype": "application/vnd.ms-word.document.macroenabled.12", "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}
        ]
    })

    findings = analyzer.analyze(art_att, ["CORR-ATT-1"])
    facts = [f.fact for f in findings]

    assert any("Double extension attachment observed: 'invoice.pdf.exe'" in f for f in facts)
    assert any("Macro-enabled Office attachment observed: 'financials.docm'" in f for f in facts)

    # Hash preservation check
    assert findings[0].metadata.get("attachment_hash") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ── 4. URL Analyzer Tests ──────────────────────────────────────────────────────

def test_url_analyzer_anomalies():
    analyzer = URLAnalyzer()

    art_url = make_email_artifact("A-URL-1", raw_fields={
        "body_text": "Please verify your account at http://192.168.1.100/login or http://xn--80ak6aa9b.com/update or http://login-verify.xyz/auth or http://user:pass@domain.com/page"
    })

    findings = analyzer.analyze(art_url, ["CORR-URL-1"])
    facts = [f.fact for f in findings]

    assert any("IP-literal URL observed" in f for f in facts)
    assert any("Punycode encoded domain observed" in f for f in facts)
    assert any("Suspicious TLD '.xyz' observed" in f for f in facts)
    assert any("Embedded user credentials observed" in f for f in facts)


# ── 5. Phishing Analyzer Composite Tests ─────────────────────────────────────

def test_phishing_analyzer_composite_finding():
    analyzer = PhishingAnalyzer()

    # Clean email
    art_clean = make_email_artifact("A-CLEAN", raw_fields={
        "sender": "Alice <alice@company.com>",
        "reply_to": "alice@company.com",
        "subject": "Team meeting notes",
        "body_text": "Hi team, here are the meeting notes.",
        "authentication_results": "spf=pass dkim=pass dmarc=pass"
    })
    clean_findings = analyzer.analyze(art_clean, ["CORR-CLEAN"])
    assert len(clean_findings) == 0

    # Phishing email with multiple indicators
    art_phish = make_email_artifact("A-PHISH", raw_fields={
        "sender": "IT Support <support@company.com>",
        "reply_to": "hacker@evil.com",
        "subject": "URGENT ACTION REQUIRED: Password reset needed immediately",
        "body_text": "Your account is suspended. Click http://login-verify.xyz to reset password.",
        "authentication_results": "dmarc=fail",
        "attachments": [{"filename": "invoice.pdf.exe", "mimetype": "application/octet-stream"}]
    })

    phish_findings = analyzer.analyze(art_phish, ["CORR-PHISH"])
    assert len(phish_findings) >= 1
    assert "Multiple phishing indicators observed" in phish_findings[0].fact
    assert phish_findings[0].mitre_mapping == "T1566"


# ── 6. Mailbox Timeline Analyzer Tests ────────────────────────────────────────

def test_mailbox_timeline_analyzer():
    analyzer = MailboxTimelineAnalyzer()

    dt = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)
    art_time = make_email_artifact("A-TIME-1", ts=dt, raw_fields={
        "sender": "sender@domain.com",
        "recipients": "rcpt@domain.com"
    })

    findings = analyzer.analyze(art_time, ["CORR-TIME-1"])
    assert len(findings) == 1
    assert findings[0].layer == "email.mailbox_timeline_analyzer"
    assert "Email event timeline recorded" in findings[0].fact


# ── 7. Engine & Orchestrator Integration Tests ─────────────────────────────────

def test_email_engine_dispatch_and_orchestrator_integration():
    art_email = make_email_artifact("A-INT-EMAIL", "email", raw_fields={
        "sender": "CEO <ceo@company.com>",
        "reply_to": "attacker@evil.com",
        "subject": "Security Alert: Verify your account",
        "body_text": "Please visit http://192.168.1.1/login",
        "authentication_results": "dmarc=fail"
    })
    art_dummy = make_email_artifact("A-DUMMY-PADDING-999", "email", raw_fields={"sender": "test@test.com"})

    fcr = make_fcr("CORR-00100", ["A-INT-EMAIL", "A-DUMMY-PADDING-999"])
    artifacts_store = {"A-INT-EMAIL": art_email, "A-DUMMY-PADDING-999": art_dummy}

    # Router check
    engines = route_fcr(fcr, artifacts_store)
    assert "email" in engines

    # Orchestrator batch execution
    mock_fir_repo = MagicMock(spec=FIRRepository)
    test_store = UnifiedEvidenceStore()

    result_findings = process_fcr_batch(
        case_id="CASE-EMAIL-101",
        fcr_objects=[fcr],
        artifacts_by_id=artifacts_store,
        fir_repo=mock_fir_repo,
        store=test_store
    )

    assert len(result_findings) >= 3
    assert mock_fir_repo.insert.called

    # FIR finding evidence reference list check
    fir_args = mock_fir_repo.insert.call_args[0][0]
    assert isinstance(fir_args, FIRFinding)
    assert isinstance(fir_args.evidence_reference, list)
    assert "CORR-00100" in fir_args.evidence_reference

    # Unified store check
    stored = test_store.read_findings("CASE-EMAIL-101")
    assert len(stored) >= 3


# ── 8. Security AST Inspection Test ───────────────────────────────────────────

def test_email_analysis_ast_security_inspection():
    """
    Verifies that all Python files in email_analysis contain 0 eval, 0 exec,
    0 shell=True, 0 os.system, 0 pickle.loads.
    """
    email_pkg_dir = os.path.join(os.path.dirname(__file__), "..", "..", "forensic_analysis", "email_analysis")
    python_files = [
        os.path.join(email_pkg_dir, f)
        for f in os.listdir(email_pkg_dir)
        if f.endswith(".py")
    ]

    assert len(python_files) >= 7

    for filepath in python_files:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            code = f.read()

        tree = ast.parse(code, filename=filepath)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec")
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        pytest.fail(f"Forbidden os.system in {filepath}")
                    if node.func.attr == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                        pytest.fail(f"Forbidden pickle.loads in {filepath}")
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        pytest.fail(f"Forbidden shell=True in {filepath}")
