import json
from unittest.mock import MagicMock
from agents.agent3_attack_reconstruction.agent import AttackReconstructionAgent
from fir.schemas import FIRFinding
from datetime import datetime, timezone

def run_test():
    sample_fir_findings = [
        FIRFinding(
            finding_id="F-101",
            case_id="CASE-AGENT3-TEST",
            tenant_id="default",
            fact="User admin logged in from IP 10.0.0.5 and executed powershell.exe with encoded payload.",
            confidence=0.95,
            severity="critical",
            timestamp=datetime(2026, 9, 23, 11, 30, 0, tzinfo=timezone.utc),
            evidence_reference=["EVD-001"],
            layer="auth_analysis"
        ),
        FIRFinding(
            finding_id="F-102",
            case_id="CASE-AGENT3-TEST",
            tenant_id="default",
            fact="Network traffic from host desktop-01 to IP 192.168.1.50 transmitting 100KB.",
            confidence=0.85,
            severity="high",
            timestamp=datetime(2026, 9, 23, 11, 35, 0, tzinfo=timezone.utc),
            evidence_reference=["EVD-002"],
            layer="network_analysis"
        )
    ]

    mock_model = MagicMock()
    mock_model.generate.return_value = json.dumps({
        "claims": [
            {
                "claim_id": "CLM-AG3-001",
                "summary": "Initial Access and Lateral Movement",
                "findings_summary": "The attack started with an admin login from 10.0.0.5 leading to malicious powershell execution, followed by C2 communication to 192.168.1.50.",
                "cited_evidence_ids": ["F-101", "F-102"],
                "assessed_importance": "critical",
                "confidence_score": 0.90,
                "missing_evidence_noted": ["Missing initial phishing email or exploit artifact."],
                "uncertainties_or_conflicts": [],
                "reasoning_notes": "The timestamp of F-101 directly precedes F-102, indicating a clear sequence from initial payload execution to C2 beaconing."
            }
        ]
    })

    mock_fir = MagicMock()
    mock_fir.get_by_case.return_value = sample_fir_findings

    mock_gateway = MagicMock()
    mock_gateway.sanitize_finding.side_effect = lambda f: MagicMock(
        xml_evidence_block=f"<finding id='{f.finding_id}'>{f.fact}</finding>",
        injection_flagged=False
    )

    agent = AttackReconstructionAgent(
        model=mock_model,
        fir_repo=mock_fir,
        sanitization_gateway=mock_gateway,
        tenant_id="default"
    )

    result = agent.run("CASE-AGENT3-TEST")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    run_test()
