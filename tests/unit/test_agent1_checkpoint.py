"""
Unit tests for Agent 1 Checkpoint & Resume mechanism (Phase 3).
"""

import pytest
import uuid
import json
from agents.agent1_evidence_intelligence.checkpoint import Agent1CheckpointManager
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from fir.schemas import FIRFinding


class MockLLMForTest:
    def __init__(self):
        self.call_count = 0

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        self.call_count += 1
        return json.dumps({
            "investigation_readiness": "READY",
            "possible_analyses": ["MFT timeline analysis"],
            "performed_analyses": ["Filesystem record parsing"],
            "evidence_trust_score": 0.95,
            "claims": [
                {
                    "claim_id": f"CLM-TEST-{self.call_count:03d}",
                    "summary": f"Verified filesystem artifact in batch iteration {self.call_count}",
                    "findings_summary": "Ingested test FIR findings",
                    "cited_evidence_ids": ["FIR-TEST-0001"],
                    "assessed_importance": "high",
                    "confidence_score": 0.95,
                    "reasoning_notes": "Correlated sector metadata"
                }
            ]
        })


def test_checkpoint_manager_save_and_skip():
    run_id = f"RUN-TEST-{uuid.uuid4().hex[:8]}"
    ckpt_mgr = Agent1CheckpointManager(run_id=run_id)

    # Initial state: no batches completed
    assert not ckpt_mgr.is_batch_completed("batch-1")

    # Mark batch-1 completed
    ckpt_mgr.mark_batch_completed(
        case_id="CASE-TEST-001",
        batch_id="batch-1",
        batch_number=1,
        fir_range="1-10",
        claims_count=1
    )

    # Verify batch-1 is completed and batch-2 is incomplete
    assert ckpt_mgr.is_batch_completed("batch-1")
    assert not ckpt_mgr.is_batch_completed("batch-2")

    # Re-instantiate checkpoint manager with same run_id
    ckpt_mgr_reloaded = Agent1CheckpointManager(run_id=run_id)
    assert ckpt_mgr_reloaded.is_batch_completed("batch-1")


def test_checkpoint_resume_interrupted_run():
    run_id = f"RUN-RESUME-{uuid.uuid4().hex[:8]}"
    mock_llm = MockLLMForTest()
    
    finding1 = FIRFinding(
        finding_id="FIR-TEST-0001",
        case_id="CASE-RESUME-001",
        tenant_id="default",
        fact="Filesystem record 1",
        confidence=0.9,
        severity="medium",
        evidence_reference=["EVID-TEST-1"],
        layer="endpoint"
    )
    finding2 = FIRFinding(
        finding_id="FIR-TEST-0002",
        case_id="CASE-RESUME-001",
        tenant_id="default",
        fact="Filesystem record 2",
        confidence=0.9,
        severity="medium",
        evidence_reference=["EVID-TEST-2"],
        layer="endpoint"
    )

    batches = [
        ("batch-1", [finding1]),
        ("batch-2", [finding2])
    ]

    # --- Run 1: Batch 1 completes, Batch 2 is interrupted ---
    ckpt_mgr1 = Agent1CheckpointManager(run_id=run_id)
    processed_claims_run1 = []

    for batch_id, findings in batches:
        if ckpt_mgr1.is_batch_completed(batch_id):
            continue

        if batch_id == "batch-2":
            # Simulate crash / process interruption during batch 2 without marking completed
            break

        # Execute batch 1
        resp = mock_llm.generate("Test prompt 1")
        processed_claims_run1.append(resp)
        ckpt_mgr1.mark_batch_completed(
            case_id="CASE-RESUME-001",
            batch_id=batch_id,
            batch_number=1,
            fir_range="1-1",
            claims_count=1
        )

    assert mock_llm.call_count == 1
    assert len(processed_claims_run1) == 1
    assert ckpt_mgr1.is_batch_completed("batch-1")
    assert not ckpt_mgr1.is_batch_completed("batch-2")

    # --- Run 2: Resume with same run_id ---
    ckpt_mgr2 = Agent1CheckpointManager(run_id=run_id)
    processed_claims_run2 = []

    for batch_id, findings in batches:
        if ckpt_mgr2.is_batch_completed(batch_id):
            # Batch 1 skipped!
            continue

        # Execute interrupted batch 2
        resp = mock_llm.generate("Test prompt 2")
        processed_claims_run2.append(resp)
        ckpt_mgr2.mark_batch_completed(
            case_id="CASE-RESUME-001",
            batch_id=batch_id,
            batch_number=2,
            fir_range="2-2",
            claims_count=1
        )

    # Batch 1 was skipped, batch 2 executed!
    assert mock_llm.call_count == 2
    assert len(processed_claims_run2) == 1
    assert ckpt_mgr2.is_batch_completed("batch-1")
    assert ckpt_mgr2.is_batch_completed("batch-2")
