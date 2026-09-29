"""
ARGUS — PHASE 2: CONTROLLED QWEN3-8B OUTPUT-GENERATION EXPERIMENT
===================================================================
Controlled, reproducible experiment comparing Baseline vs Conservative Output Constraint (num_predict=2048).
Uses exact same 50 FIR findings, exact system/user prompts, real Qwen3-8B Ollama model, and Agent1Validator.
No production changes made.
"""

import sys
import os
import time
import json
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("phase2_experiment")

from config.settings import settings
from fir.schemas import FIRFinding
from sanitization.gateway import SanitizationGateway
from models.llm import LLMLoader, OllamaWrapper
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.prompts import AGENT1_SYSTEM_PROMPT, build_agent1_user_prompt
from agents.agent1_evidence_intelligence.schemas import Agent1Output, Agent1Claim

# Custom wrapper allowing explicit options parameter for the experiment
class ExperimentOllamaWrapper:
    def __init__(self, model_name: str, base_url: str, timeout: int = 600, options: dict = None):
        self.model_name = model_name
        self.base_url = base_url
        self.timeout = timeout
        self.options = options or {}

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        url = f"{self.base_url}/api/generate"
        model_name = self.model_name
        if model_name in ("Qwen/Qwen3-8B", "Qwen3-8B"):
            model_name = "qwen3:8b"
        elif "/" in model_name:
            model_name = model_name.split("/")[-1]

        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False
        }
        if system_prompt:
            payload["system"] = system_prompt
        if self.options:
            payload["options"] = self.options

        r = requests.post(url, json=payload, timeout=self.timeout)
        if r.status_code == 200:
            return r.json().get("response", "")
        else:
            raise RuntimeError(f"Ollama returned error status: {r.status_code}")

def run_experiment_on_batch(wrapper, s_batch, case_id="CASE-2020JIMMYWILSON-E01"):
    gateway = SanitizationGateway()
    agent = EvidenceIntelligenceAgent(
        model=wrapper,
        sanitization_gateway=gateway,
        tenant_id="default"
    )

    t0 = time.time()
    res = agent.run(case_id=case_id, context={"fir_findings": s_batch, "tenant_id": "default"})
    t1 = time.time()
    wall_sec = round(t1 - t0, 2)

    return res, wall_sec

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print("ARGUS — PHASE 2: CONTROLLED QWEN3-8B OUTPUT-GENERATION EXPERIMENT")
    print("=" * 80)

    # Load exact 50 FIR findings from scratch/full_3286_sanitized_findings.json
    json_path = ARGUS_ROOT / "scratch" / "full_3286_sanitized_findings.json"
    with open(json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    batch_50_raw = raw_data[:50]
    fir_batch = []
    for item in batch_50_raw:
        fid = item["finding_id"]
        ev_ref = item.get("evidence_reference") or ["EVID-3286-DEFAULT"]
        if isinstance(ev_ref, str):
            ev_ref = [ev_ref]

        ts_str = item.get("timestamp")
        parsed_ts = None
        if ts_str:
            try:
                parsed_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                parsed_ts = datetime.now(timezone.utc)

        finding_obj = FIRFinding(
            finding_id=fid,
            case_id=item.get("case_id", "CASE-2020JIMMYWILSON-E01"),
            tenant_id=item.get("tenant_id", "default"),
            fact=item.get("sanitized_fact") or "Filesystem artifact record",
            sanitized_fact=item.get("sanitized_fact"),
            injection_flagged=item.get("injection_flagged", False),
            injection_score=item.get("injection_score", 0.0),
            confidence=item.get("confidence", 0.88),
            severity=item.get("severity", "informational"),
            mitre_mapping=item.get("mitre_mapping"),
            timestamp=parsed_ts,
            evidence_reference=ev_ref,
            layer=item.get("layer", "endpoint.filesystem_analyzer"),
            source_artifact_id=item.get("source_artifact_id")
        )
        fir_batch.append(finding_obj)

    print(f"\n[EXPERIMENTAL FIXTURE]: Loaded fixed batch of {len(fir_batch)} FIR findings.")

    # 1. RUN BASELINE (Unconstrained OllamaWrapper generation)
    print("\n" + "=" * 70)
    print("RUN 1: BASELINE (Current Production OllamaWrapper Unconstrained Configuration)")
    print("=" * 70)
    baseline_wrapper = ExperimentOllamaWrapper(
        model_name="qwen3:8b",
        base_url="http://localhost:11434",
        options={}  # Baseline: no options dict in payload
    )
    res_baseline, wall_baseline = run_experiment_on_batch(baseline_wrapper, fir_batch)
    print(f"--> Baseline Wall Time: {wall_baseline} s")
    print(f"--> Execution Status : {res_baseline.get('execution_status')}")
    print(f"--> Claims Count     : {len(res_baseline.get('claims', []))}")

    # 2. RUN TESTED CANDIDATE (Conservative num_predict=2048)
    print("\n" + "=" * 70)
    print("RUN 2: TESTED CANDIDATE (options={'num_predict': 2048})")
    print("=" * 70)
    candidate_wrapper = ExperimentOllamaWrapper(
        model_name="qwen3:8b",
        base_url="http://localhost:11434",
        options={"num_predict": 2048}
    )
    res_candidate, wall_candidate = run_experiment_on_batch(candidate_wrapper, fir_batch)
    print(f"--> Candidate Wall Time: {wall_candidate} s")
    print(f"--> Execution Status   : {res_candidate.get('execution_status')}")
    print(f"--> Claims Count       : {len(res_candidate.get('claims', []))}")

    # Save detailed experiment log
    exp_results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fixture_fir_count": 50,
        "baseline": {
            "wall_sec": wall_baseline,
            "result": res_baseline
        },
        "candidate_num_predict_2048": {
            "wall_sec": wall_candidate,
            "result": res_candidate
        }
    }

    out_json_path = ARGUS_ROOT / "scratch" / "phase2_experiment_results.json"
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(exp_results, f, indent=2, default=str)
    print(f"\n[+] Saved detailed experiment raw log to: {out_json_path}")

if __name__ == "__main__":
    main()
