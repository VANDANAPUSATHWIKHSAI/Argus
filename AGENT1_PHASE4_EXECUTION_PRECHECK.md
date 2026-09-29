# ARGUS — AGENT 1 PHASE 4: FULL-CORPUS EXECUTION PRE-RUN SNAPSHOT

## 1. PRE-RUN EXECUTION SNAPSHOT

- **Execution Run ID**: `RUN-AGENT1-5002-20260925`
- **Target Evidence Image**: `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01`
- **Target Case ID**: `CASE-2020JW-5002` (Correlated Domain Finding Case)
- **Authoritative Corpus Size**: Exactly **5,002 FIR Findings** (Correlated Domain Findings)
- **Batch Size Configuration**: **50 FIRs per batch**
- **Total Batch Count**: **101 Batches** (100 batches of 50 FIRs + 1 remainder batch of 2 FIRs)
- **Model Name**: `Qwen/Qwen3-8B` (`qwen3:8b` Q4_K_M via Ollama)
- **Ollama Base URL**: `http://localhost:11434`
- **Effective HTTP Timeout**: **600 seconds** (10.0 minutes via `OLLAMA_TIMEOUT`)
- **Git Branch**: `agent-1`
- **Git Commit SHA**: `e9c8af2d7d81698e4ab606e55b3823542d40fd27`
- **PostgreSQL Host / Port**: `localhost:5433` (Database: `argus`)
- **Hardware Target**: NVIDIA GeForce RTX 3050 Laptop GPU (6GB VRAM)
- **Pre-Run Checkpoint Count**: **0** (Clean run start for `RUN-AGENT1-5002-20260925`)
- **Pre-Run Output Row Count**: **0** (for `case_id = 'CASE-2020JW-5002'`)
- **Execution Timestamp**: `2026-09-25T16:45:00Z`

---

## 2. PRE-RUN VERIFICATION GATES

| Verification Check | Target Requirement | Status |
| :--- | :--- | :--- |
| **Evidence File Integrity** | `2020JimmyWilson.E01` present & readable | **PASS** |
| **Corpus Identity** | Exactly 5,002 correlated domain FIR findings | **PASS** |
| **Batch Plan** | 101 batches (50/batch, final batch = 2) | **PASS** |
| **Model Endpoint** | Ollama local endpoint `http://localhost:11434` responsive | **PASS** |
| **HTTP Timeout** | Configured to 600s (`models/llm.py`) | **PASS** |
| **Database Idempotency** | Unique index + UPSERT active (`agent.py`) | **PASS** |
| **Checkpoint Storage** | PostgreSQL `agent_checkpoints` table initialized | **PASS** |
| **Deterministic Run ID** | `RUN-AGENT1-5002-20260925` bound across batches | **PASS** |

---

## 3. EXECUTION STRATEGY

1. **Early Real-Evidence Gate**: Process **Batches 1, 2, and 3** (150 FIRs), automatically halt, and perform 12-point forensic quality and transaction audit.
2. **Full-Corpus Background Run**: Upon passing early gate, automatically resume execution for **Batches 4 through 101** with persistent logging to `logs/agent1_full_corpus_RUN-AGENT1-5002-20260925.log`.
