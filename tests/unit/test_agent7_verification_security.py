from types import SimpleNamespace

from agents.agent7_supervisor.call2_verification import SupervisorVerification


class Repository:
    def __init__(self, record):
        self.record = record

    def get_by_id(self, tenant_id, finding_id):
        if tenant_id == self.record.tenant_id and finding_id == self.record.finding_id:
            return self.record
        return None


class Model:
    def generate(self, prompt):
        return "YES"


class Gateway:
    def sanitize(self, text, field_name):
        return text


def verifier(record):
    return SupervisorVerification(
        Model(), Repository(record), Gateway(), tenant_id=record.tenant_id
    )


def test_empty_evidence_cannot_verify():
    record = SimpleNamespace(
        finding_id="F-1", case_id="C-1", tenant_id="T-1",
        sanitized_fact="evidence", fact="evidence", severity="low"
    )
    result = verifier(record).verify({"case_id": "C-1", "tenant_id": "T-1", "claim": "evidence"})
    assert result["verified"] is False
    assert result["checks"]["existence"] is False


def test_wrong_case_and_tenant_cannot_verify():
    record = SimpleNamespace(
        finding_id="F-1", case_id="C-1", tenant_id="T-1",
        sanitized_fact="evidence", fact="evidence", severity="low"
    )
    agent = verifier(record)
    wrong_case = agent.verify({
        "case_id": "C-2", "tenant_id": "T-1", "claim": "evidence", "evidence_ids": ["F-1"]
    })
    wrong_tenant = agent.verify({
        "case_id": "C-1", "tenant_id": "T-2", "claim": "evidence", "evidence_ids": ["F-1"]
    })
    assert wrong_case["verified"] is False
    assert wrong_tenant["verified"] is False


def test_authoritative_scoped_evidence_is_required_for_success(monkeypatch):
    record = SimpleNamespace(
        finding_id="F-1", case_id="C-1", tenant_id="T-1",
        sanitized_fact="evidence", fact="evidence", severity="low"
    )
    monkeypatch.setattr(
        "models.classifiers.ClassifierLoader.load_mnli",
        lambda self: lambda **kwargs: {
            "labels": ["supports", "neutral", "contradicts"],
            "scores": [0.99, 0.005, 0.005],
        },
    )
    result = verifier(record).verify({
        "case_id": "C-1",
        "tenant_id": "T-1",
        "claim": "evidence",
        "evidence_ids": ["F-1"],
    })
    assert result["verified"] is True


def test_claimed_severity_must_match_authoritative_evidence(monkeypatch):
    record = SimpleNamespace(
        finding_id="F-1", case_id="C-1", tenant_id="T-1",
        sanitized_fact="evidence", fact="evidence", severity="low"
    )
    monkeypatch.setattr(
        "models.classifiers.ClassifierLoader.load_mnli",
        lambda self: lambda **kwargs: {
            "labels": ["supports", "neutral", "contradicts"],
            "scores": [0.99, 0.005, 0.005],
        },
    )
    result = verifier(record).verify({
        "case_id": "C-1", "tenant_id": "T-1", "claim": "evidence",
        "severity": "critical", "evidence_ids": ["F-1"],
    })
    assert result["verified"] is False
    assert result["checks"]["severity"] is False


def test_conflicting_deterministic_label_cannot_verify():
    record = SimpleNamespace(
        finding_id="F-1", case_id="C-1", tenant_id="T-1",
        sanitized_fact="evidence", fact="evidence", severity="low"
    )
    result = verifier(record).verify({
        "case_id": "C-1", "tenant_id": "T-1", "claim": "evidence",
        "deterministic_label": "benign", "label": "malicious",
        "evidence_ids": ["F-1"],
    })
    assert result["verified"] is False
    assert result["checks"]["divergence"] is False


def test_high_claim_score_without_evidence_support_cannot_verify(monkeypatch):
    record = SimpleNamespace(
        finding_id="F-1", case_id="C-1", tenant_id="T-1",
        sanitized_fact="A benign document was opened.", fact="A benign document was opened.",
        severity="low"
    )
    monkeypatch.setattr(
        "models.classifiers.ClassifierLoader.load_mnli",
        lambda self: lambda **kwargs: {
            "labels": ["supports", "neutral", "contradicts"],
            "scores": [0.99, 0.005, 0.005],
        },
    )
    monkeypatch.setattr(
        SupervisorVerification,
        "sanitized_context_fetch",
        lambda self, *_args, **_kwargs: record.sanitized_fact,
    )
    result = verifier(record).verify({
        "case_id": "C-1", "tenant_id": "T-1",
        "claim": "The attacker obtained administrator credentials.",
        "evidence_ids": ["F-1"],
    })
    assert result["verified"] is False
