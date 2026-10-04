from unittest.mock import MagicMock
from agents.agent3_attack_reconstruction.schemas import (
    Agent3Output, InfectionPath, AttackPathStep, LateralMovement
)
from agents.agent3_attack_reconstruction.graph_writer import AttackPathGraphWriter


def test_attack_path_graph_writer_cypher_calls():
    mock_neo4j = MagicMock()
    writer = AttackPathGraphWriter(neo4j_client=mock_neo4j)

    output = Agent3Output(
        case_id="CASE-TEST-GRAPH",
        tenant_id="default",
        model_used="Qwen3-8B",
        infection_path=InfectionPath(
            entry_point="Phishing email with attachment",
            evidence_ids=["FIR-001"],
            confidence=0.95
        ),
        attack_path=[
            AttackPathStep(
                step_number=1,
                stage="Initial Access",
                description="Malicious attachment opened",
                evidence_ids=["FIR-001"],
                confidence=0.95
            ),
            AttackPathStep(
                step_number=2,
                stage="Execution",
                description="PowerShell process spawned",
                evidence_ids=["FIR-002"],
                confidence=0.90
            )
        ],
        lateral_movement=[
            LateralMovement(
                source_host="HOST-A",
                destination_host="HOST-B",
                method="SMB",
                evidence_ids=["FIR-003"],
                confidence=0.88
            )
        ],
        reconstruction_summary="Test attack path graph generation",
        overall_confidence=0.91
    )

    success = writer.sync_attack_path(output)
    assert success is True
    assert mock_neo4j.query.call_count >= 5

    # Inspect executed Cypher queries
    cypher_calls = [call[0][0] for call in mock_neo4j.query.call_args_list]
    assert any("AttackStep" in q for q in cypher_calls)
    assert any("NEXT" in q for q in cypher_calls)
    assert any("SUPPORTED_BY" in q for q in cypher_calls)
    assert any("LATERAL_MOVEMENT" in q for q in cypher_calls)
