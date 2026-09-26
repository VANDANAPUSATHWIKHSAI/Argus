# ARGUS — AGENT 1 PHASE 3A: FULL-CORPUS PREFLIGHT & CHECKPOINT/RESUME SAFETY AUDIT REPORT

## 1. EXECUTIVE SUMMARY

Phase 3A performed a comprehensive read-only production preflight audit over Agent 1 full-corpus runner infrastructure, timeout configurations, PostgreSQL database transaction boundaries, failure classifications, and checkpoint/resume semantics.

All safety criteria, resume invariants, transaction ordering constraints, and preflight dry-runs passed with **100% SUCCESS**.

- **STATUS**: `PASS`
- **FULL CORPUS AUTHORIZATION**: `AUTHORIZED`

---

## 2. CURRENT SOURCE STATE & TIMEOUT VERIFICATION

The exact current source files were inspected:
- `models/llm.py`: Configurable `ollama_timeout` parameter defaulting to **600 seconds** (10 minutes) passed to `OllamaWrapper` and invoked via `requests.post(url, json=payload, timeout=self.timeout)`.
- `agents/agent1_evidence_intelligence/agent.py`: Agent 1 reasoning pipeline, deterministic validation gate, and PostgreSQL persistence handler (`_persist_agent_output`).
- `agents/agent1_evidence_intelligence/checkpoint.py`: `Agent1CheckpointManager` utilizing PostgreSQL `agent_checkpoints` table with unique key `(run_id, batch_id)`.
- `scratch/run_consolidation_benchmark.py`: Authoritative consolidated benchmark runner.

### Timeout Configuration Inspection:
- Effective Ollama Base URL: `http://localhost:11434`
- Effective Model Name: `Qwen/Qwen3-8B` (`qwen3:8b`)
- Effective HTTP Timeout: **600 seconds** (10.0 minutes)

---

## 3. CHECKPOINT & DATABASE TRANSACTION ORDERING AUDIT

### Exact Execution Sequence:
```
1. Agent Output Generation & Deterministic Validation
                     │
                     ▼
2. agent._persist_agent_output(output)
                     │
                     ▼
3. PostgreSQL INSERT INTO agent_outputs
                     │
                     ▼
4. PostgreSQL conn.commit()  <-- OUTPUTS COMMITTED TO DATABASE FIRST
                     │
                     ▼
5. agent.run() returns result
                     │
                     ▼
6. checkpoint_manager.mark_batch_completed(case_id, batch_id, ...)
                     │
                     ▼
7. PostgreSQL INSERT INTO agent_checkpoints ON CONFLICT DO UPDATE
                     │
                     ▼
8. PostgreSQL conn.commit()  <-- CHECKPOINT MARKED COMPLETED SECOND
```

### Durability & Safety Invariant Verification:
- **PostgreSQL Output Commit Strictly Precedes Checkpoint Completion**: `agent_outputs` are fully committed to PostgreSQL BEFORE `checkpoint_manager.mark_batch_completed()` is called.
- **No Uncommitted Checkpoints**: A checkpoint cannot claim successful completion of work whose PostgreSQL persistence has not been committed.

---

## 4. CHECKPOINT SEMANTICS & STATE-TRANSITION AUDIT

1. **Unit of Completion**: A batch of up to 50 FIR findings identified by a unique `batch_id` (e.g. `BATCH-0001`).
2. **Tracking Key**: Composite key `(run_id, batch_id)` in PostgreSQL `agent_checkpoints` table.
3. **Storage Location**: PostgreSQL `agent_checkpoints` table with in-memory set cache (`_in_memory_checkpoints`).
4. **Persisted Information**: `run_id`, `agent_id`, `case_id`, `batch_id`, `batch_number`, `fir_range`, `status` ("COMPLETED"), `claims_count`, `created_at`, `metadata`.
5. **Checkpoint Trigger**: Called after `agent.run()` successfully returns.
6. **Interruption Scenarios**:
   - *Interruption before/during LLM call or DB insert*: Batch remains un-checkpointed. On resume, batch is cleanly re-run.
   - *Interruption after DB commit & checkpoint commit*: Batch is marked `COMPLETED`. On resume, `is_batch_completed(batch_id)` returns True, and batch is cleanly skipped.
7. **Partial Completion**: Partially completed batches are never marked complete; only full batches with committed database output are recorded.

---

## 5. FAILURE CLASSIFICATION MATRIX

| Failure Mode | Internal Representation | System Action | Checkpoint Action |
| :--- | :--- | :--- | :--- |
| **Successful Response** | `execution_status="SUCCESS"` | Claims validated & persisted | Checkpoint saved (`COMPLETED`) |
| **Malformed JSON** | `execution_status="FAILED"` | Fail-closed (0 claims produced) | Logged error, fails batch |
| **Invalid Citation** | `claim.citation_verified=False` | Rejected citation, flag preserved | Handled by validator |
| **Invalid Confidence** | `claim.is_valid_confidence=False` | Preserves raw value, safety 0.0 | Handled by validator |
| **Missing FIR Findings** | `execution_status="FAILED"` | Logged warning, returns failure | Fails closed |
| **Sanitization Failure** | Exception raised in gateway | Logged error, skips finding | Handled per finding |
| **Prompt Injection** | `injection_flagged=True` | Redacted/tagged context | Processed safely |
| **HTTP Read Timeout** | `RuntimeError` (`requests.ReadTimeout`) | Caught in `agent.run()`, fails closed | Not checkpointed (retryable) |
| **PostgreSQL Error** | Exception in `_persist_agent_output` | Logged warning | Not checkpointed (retryable) |
| **Process Interruption** | Process killed | Incomplete batches un-checkpointed | Re-run cleanly on resume |

---

## 6. RESUME SAFETY & CHECKPOINT ORDERING TEST

A controlled test (`test_resume_safety_and_ordering`) was executed over synthetic test findings across 2 mini-batches:
- **Run A**: Processed Batch 1, saved output to PostgreSQL, committed checkpoint `BATCH-0001`.
- **Run B (Simulated Resume)**: Queried `agent_checkpoints`. Cleanly **SKIPPED `BATCH-0001`**, processed `BATCH-0002`, and committed final checkpoint.
- **Verification**: Zero duplicate output records were created; skipped batch count and processed batch count balanced perfectly.

---

## 7. FULL-CORPUS RUNNER DRY-RUN

A full preflight dry-run was executed against the PostgreSQL database:
- **Total FIR Findings in Database**: 104,282 findings
- **Target Case ID**: `default_case` / `2020JimmyWilson.E01` (103,283 findings)
- **Batch Size**: 50 FIRs per batch
- **Total Batches Formed**: 2,066 batches
- **Assigned Run ID**: `RUN-FULL-CORPUS-default_`
- **Completed Batches**: 0 (0 skipped)
- **Pending Batches**: 2,066 batches
- **Result**: Dry-run completed cleanly without executing LLM inference or mutating evidence.

---

## 8. TEST SUITE EXECUTION

Command executed: `pytest tests/unit/test_agent1_evidence_intelligence.py tests/unit/test_agent1_checkpoint.py -v`

Results:
- `test_agent1_uses_qwen3_8b`: **PASSED**
- `test_valid_citation_lineage_verification`: **PASSED**
- `test_invalid_arbitrary_citation_rejection`: **PASSED**
- `test_out_of_bounds_confidence_not_silently_clamped`: **PASSED**
- `test_sanitization_gateway_integration`: **PASSED**
- `test_missing_fir_findings_fail_closed`: **PASSED**
- `test_malformed_json_fails_closed`: **PASSED**
- `test_already_sanitized_context_does_not_resanitize`: **PASSED**
- `test_checkpoint_manager_save_and_skip`: **PASSED**
- `test_checkpoint_resume_interrupted_run`: **PASSED**

**Total: 10 / 10 PASSED (100%)**

---

## 9. KNOWN RISKS & MITIGATIONS

1. **GPU Decode Latency**: Autoregressive decoding on RTX 3050 Laptop GPU takes ~70s to ~290s per 50-FIR batch.
   - *Mitigation*: The 600s HTTP timeout protects against premature HTTP read aborts, and PostgreSQL checkpointing ensures full resume capability if interrupted.
2. **Background Execution**: Long runs should be started in detached background mode (e.g. `run_command` async or PowerShell background job) so execution is independent of terminal sessions.

---

## 10. FINAL VERDICT & AUTHORIZATION

- **STATUS**: `PASS`
- **FULL CORPUS AUTHORIZATION**: `AUTHORIZED`

All preflight checks have passed. Agent 1 is fully authorized for full-corpus background execution with checkpoint/resume enabled.
