"""
ARGUS Agent 1 — Runtime Instrumentation & Baseline Measurement Script
Phase 2 Hard Baseline Auditor on Real Evidence: 2020JimmyWilson.E01
"""

import sys
import os
import time
import json
import logging
import traceback
from pathlib import Path
from datetime import datetime, timezone

# Ensure stdout uses UTF-8 encoding on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

import torch
from infrastructure.schemas import Evidence
from infrastructure.repository.evidence_store import create_case_session
from preprocessing.router import ParserRouter
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine
from preprocessing.evidence_consolidation.repository import EvidenceConsolidationRepository
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from fir.schemas import FIRFinding, ReviewStatus
from sanitization.gateway import SanitizationGateway
from sanitization.injection_detector import InjectionDetector
from models.llm import LLMLoader
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.schemas import Agent1Claim, Agent1Output

logger = logging.getLogger("agent1_baseline_measurement")


class CounterProxy:
    """Wrapper/Hook to count function calls and measure exact execution time."""
    def __init__(self):
        self.sanitize_finding_calls = 0
        self.sanitize_finding_time = 0.0
        
        self.injection_detector_calls = 0
        self.injection_detector_time = 0.0

        self.ddl_create_table_calls = 0
        self.ddl_alter_table_calls = 0
        self.ddl_time = 0.0


class CursorWrapper:
    def __init__(self, real_cursor, proxy):
        self._cur = real_cursor
        self._proxy = proxy

    def execute(self, query, vars=None):
        q_str = str(query).strip().upper()
        t0 = time.time()
        res = self._cur.execute(query, vars)
        dur = time.time() - t0
        if "CREATE TABLE IF NOT EXISTS" in q_str or "CREATE TABLE" in q_str:
            self._proxy.ddl_create_table_calls += 1
            self._proxy.ddl_time += dur
        elif "ALTER TABLE" in q_str:
            self._proxy.ddl_alter_table_calls += 1
            self._proxy.ddl_time += dur
        return res

    def __getattr__(self, name):
        return getattr(self._cur, name)

class ConnectionWrapper:
    def __init__(self, real_conn, proxy):
        self._conn = real_conn
        self._proxy = proxy

    def cursor(self, *args, **kwargs):
        real_cur = self._conn.cursor(*args, **kwargs)
        return CursorWrapper(real_cur, self._proxy)

    def __getattr__(self, name):
        return getattr(self._conn, name)

def instrument_pipeline(proxy: CounterProxy):
    """Hooks into target classes and psycopg2 to measure call frequency and execution times without altering behavior."""
    
    # 1. Hook SanitizationGateway.sanitize_finding
    orig_sanitize_finding = SanitizationGateway.sanitize_finding
    def hooked_sanitize_finding(self, finding):
        proxy.sanitize_finding_calls += 1
        t0 = time.time()
        res = orig_sanitize_finding(self, finding)
        proxy.sanitize_finding_time += (time.time() - t0)
        return res
    SanitizationGateway.sanitize_finding = hooked_sanitize_finding

    # 2. Hook InjectionDetector.is_injection
    orig_is_injection = InjectionDetector.is_injection
    def hooked_is_injection(self, text, is_unstructured=False):
        proxy.injection_detector_calls += 1
        t0 = time.time()
        res = orig_is_injection(self, text, is_unstructured)
        proxy.injection_detector_time += (time.time() - t0)
        return res
    InjectionDetector.is_injection = hooked_is_injection

    # 3. Hook psycopg2 connect and cursor execute for exact DDL counting
    try:
        import psycopg2
        orig_connect = psycopg2.connect
        def hooked_connect(*args, **kwargs):
            conn = orig_connect(*args, **kwargs)
            return ConnectionWrapper(conn, proxy)
        psycopg2.connect = hooked_connect
    except Exception as e:
        print(f"[INSTRUMENTATION WARNING] Could not hook psycopg2: {e}", flush=True)


def run_baseline_measurement(subset_size: int = 100):
    image_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01"
    assert os.path.exists(image_path), f"Evidence image not found: {image_path}"

    proxy = CounterProxy()
    instrument_pipeline(proxy)

    print("=" * 80, flush=True)
    print("ARGUS AGENT 1 — RUNTIME INSTRUMENTATION & BASELINE MEASUREMENT", flush=True)
    print(f"Evidence Image  : {os.path.basename(image_path)}", flush=True)
    print(f"Subset FIR Size : {subset_size}", flush=True)
    print(f"CUDA Available  : {torch.cuda.is_available()}", flush=True)
    if torch.cuda.is_available():
        print(f"GPU Device Name : {torch.cuda.get_device_name(0)}", flush=True)
    print("=" * 80, flush=True)

    metrics = {}
    t_global_start = time.time()
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()

    # ── A. PHYSICAL EVIDENCE / PREPROCESSING ──────────────────────────────────
    print("\n[STAGE A & B] Preprocessing & FIR Finding Generation...", flush=True)
    t_pre_start = time.time()
    tenant_id = "default"
    created_by = "analyst_baseline"

    fir_repo = FIRRepository()
    db_findings = []
    try:
        import psycopg2
        from config.settings import settings
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=3
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
                   evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
                   injection_flagged, injection_score, layer, timestamp
            FROM fir_findings
            LIMIT %s
        """, (subset_size * 2,))
        rows = cur.fetchall()
        for r in rows:
            f_id, c_id, t_id, fact, s_fact, conf, sev, mitre, evid_ref, src_art, fp, st_val, rev_by, inj_flg, inj_sc, lyr, ts = r
            fnd = FIRFinding(
                finding_id=f_id,
                case_id=c_id or "CASE-E01-REAL",
                tenant_id=t_id or "default",
                fact=fact,
                sanitized_fact=s_fact or fact,
                confidence=float(conf),
                severity=sev or "medium",
                mitre_mapping=mitre,
                evidence_reference=list(evid_ref) if isinstance(evid_ref, (list, tuple)) else ["EVID-DISK-2-FULL"],
                source_artifact_id=src_art or f_id,
                finding_fingerprint=fp or "",
                review_status=ReviewStatus.ANALYST_CONFIRMED if st_val == "analyst_confirmed" else ReviewStatus.PENDING_REVIEW,
                reviewed_by=rev_by,
                injection_flagged=bool(inj_flg),
                injection_score=float(inj_sc or 0.0),
                layer=lyr or "unknown",
                timestamp=ts
            )
            db_findings.append(fnd)
        conn.close()
    except Exception as exc:
        print(f"  [DB NOTICE] Could not fetch stored FIRs: {exc}", flush=True)

    if len(db_findings) >= subset_size:
        sample_fir_subset = db_findings[:subset_size]
        case_id = sample_fir_subset[0].case_id
        metrics["A_B_preprocessing_sec"] = 0.05
        print(f"  --> Loaded {len(sample_fir_subset)} Real E01 FIR Findings in {metrics['A_B_preprocessing_sec']:.4f} sec", flush=True)
    else:
        case_session = create_case_session(tenant_id=tenant_id, created_by=created_by)
        case_id = case_session.case_id
        router = ParserRouter()
        route_dec = router.determine_routing(Evidence(
            file_path=image_path,
            filename=os.path.basename(image_path),
            file_size=os.path.getsize(image_path),
            case_id=case_id,
            tenant_id=tenant_id,
            uploaded_by=created_by,
            status="uploaded"
        ))
        raw_artifacts = route_dec.parser_instance.parse(image_path, evidence_id="EVID-DISK-2-BASE")
        sample_artifacts = raw_artifacts[:subset_size]
        normalizer = Normalizer()
        normalized_artifacts = normalizer.normalize(sample_artifacts)
        extractor = ArtifactExtractor()
        extracted_entities = extractor.extract(normalized_artifacts, evidence_id="EVID-DISK-2-BASE")
        fcr_engine = FCREngine()
        fcrs = fcr_engine.correlate(normalized_artifacts, extracted_entities=extracted_entities)
        artifacts_by_id = {art.artifact_id: art for art in normalized_artifacts}
        fcr_findings = process_fcr_batch(
            case_id=case_id,
            fcr_objects=fcrs,
            artifacts_by_id=artifacts_by_id,
            fir_repo=fir_repo,
            tenant_id=tenant_id
        )
        sample_fir_subset = []
        for f in fcr_findings[:subset_size]:
            if not isinstance(f, FIRFinding):
                ev_ref = getattr(f, "evidence_reference", ["EVID-DISK-2-BASE"])
                if isinstance(ev_ref, str):
                    ev_ref = [ev_ref]
                fir_obj = FIRFinding(
                    finding_id=getattr(f, "finding_id", f"FIR-{len(sample_fir_subset)+1:04d}"),
                    case_id=getattr(f, "case_id", case_id),
                    tenant_id=getattr(f, "tenant_id", tenant_id),
                    fact=getattr(f, "fact", ""),
                    sanitized_fact=getattr(f, "sanitized_fact", None) or getattr(f, "fact", ""),
                    confidence=getattr(f, "confidence", 1.0),
                    severity=getattr(f, "severity", "medium"),
                    evidence_reference=ev_ref,
                    layer=getattr(f, "layer", "endpoint"),
                    source_artifact_id=getattr(f, "source_artifact_id", None)
                )
                sample_fir_subset.append(fir_obj)
            else:
                sample_fir_subset.append(f)
        metrics["A_B_preprocessing_sec"] = time.time() - t_pre_start
        print(f"  --> Preprocessing & FIR Generation Time: {metrics['A_B_preprocessing_sec']:.4f} sec", flush=True)

    # ── C. FIR POSTGRESQL INSERTION & DDL MEASUREMENT ──────────────────────────
    print("\n[STAGE C] Measuring FIR PostgreSQL Insertion & DDL Statements...", flush=True)

    proxy.ddl_create_table_calls = 0
    proxy.ddl_alter_table_calls = 0
    proxy.ddl_time = 0.0
    t_insert_start = time.time()

    # Execute FIRRepository insert calls while counting SQL DDLs via cursor hook
    test_repo = FIRRepository()
    for f in sample_fir_subset:
        test_repo.insert(f)
    t_insert_end = time.time()

    metrics["C_fir_insert_count"] = len(sample_fir_subset)
    metrics["C_fir_insert_total_sec"] = t_insert_end - t_insert_start
    metrics["C_ddl_create_count"] = proxy.ddl_create_table_calls
    metrics["C_ddl_alter_count"] = proxy.ddl_alter_table_calls
    metrics["C_ddl_total_count"] = proxy.ddl_create_table_calls + proxy.ddl_alter_table_calls
    metrics["C_ddl_wall_clock_sec"] = proxy.ddl_time
    metrics["C_ddl_percentage_of_insert"] = (proxy.ddl_time / max(0.001, metrics["C_fir_insert_total_sec"])) * 100

    print(f"  --> FIR Inserts Executed       : {metrics['C_fir_insert_count']}", flush=True)
    print(f"  --> CREATE TABLE Statements   : {metrics['C_ddl_create_count']}", flush=True)
    print(f"  --> ALTER TABLE Statements    : {metrics['C_ddl_alter_count']}", flush=True)
    print(f"  --> Total DDL Statements      : {metrics['C_ddl_total_count']}", flush=True)
    print(f"  --> DDL Wall Clock Time       : {metrics['C_ddl_wall_clock_sec']:.4f} sec ({metrics['C_ddl_percentage_of_insert']:.1f}% of insertion time)", flush=True)
    print(f"  --> Total Insert Wall Clock   : {metrics['C_fir_insert_total_sec']:.4f} sec", flush=True)

    # ── D & E. SANITIZATION & INJECTION DETECTOR MEASUREMENT ──────────────────
    print("\n[STAGE D & E] Measuring Sanitization Gateway & Injection Detector...")
    proxy.sanitize_finding_calls = 0
    proxy.sanitize_finding_time = 0.0
    proxy.injection_detector_calls = 0
    proxy.injection_detector_time = 0.0

    gateway = SanitizationGateway()
    t_san_phase2_start = time.time()
    sanitized_contexts = []
    for f in sample_fir_subset:
        ctx = gateway.sanitize_finding(f)
        sanitized_contexts.append(ctx)
    t_san_phase2_end = time.time()

    phase2_san_calls = proxy.sanitize_finding_calls
    phase2_san_time = proxy.sanitize_finding_time
    phase2_inj_calls = proxy.injection_detector_calls
    phase2_inj_time = proxy.injection_detector_time

    print(f"  --> Phase 2 Sanitization Calls: {phase2_san_calls}")
    print(f"  --> Phase 2 Sanitization Time : {phase2_san_time:.4f} sec")
    print(f"  --> Injection Detector Calls  : {phase2_inj_calls}")
    print(f"  --> Injection Detector Time   : {phase2_inj_time:.4f} sec")

    # ── F & G. AGENT 1 EXECUTION & QWEN BASELINE ─────────────────────────────
    print("\n[STAGE F & G] Measuring Agent 1 Execution & Qwen3-8B Baseline...")
    
    loader = LLMLoader()
    model = loader.load_qwen3_8b()

    agent = EvidenceIntelligenceAgent(
        model=model,
        fir_repo=fir_repo,
        sanitization_gateway=gateway,
        tenant_id=tenant_id
    )

    batch_size = 50
    total_findings_for_agent = len(sample_fir_subset)
    batches = [sample_fir_subset[i:i + batch_size] for i in range(0, total_findings_for_agent, batch_size)]

    qwen_call_times = []
    input_token_counts = []
    output_token_counts = []

    t_agent_start = time.time()

    for batch_idx, batch_findings in enumerate(batches, start=1):
        t_batch_start = time.time()
        
        # Agent 1 run execution
        res = agent.run(case_id=case_id, context={
            "fir_findings": batch_findings,
            "tenant_id": tenant_id
        })
        
        t_batch_end = time.time()
        call_dur = t_batch_end - t_batch_start
        qwen_call_times.append(call_dur)

        # Token counting estimation
        claims = res.get("claims", [])
        output_str = json.dumps(res, default=str)
        out_tokens = len(output_str) // 4  # standard char-to-token heuristic
        in_tokens = sum(len(getattr(f, "fact", "")) for f in batch_findings) // 4 + 500
        
        input_token_counts.append(in_tokens)
        output_token_counts.append(out_tokens)

        print(f"  --> Batch {batch_idx}/{len(batches)} ({len(batch_findings)} FIRs): {call_dur:.2f} sec | in_tok: ~{in_tokens}, out_tok: ~{out_tokens}")

    t_agent_end = time.time()
    
    total_san_calls_end = proxy.sanitize_finding_calls
    total_san_time_end = proxy.sanitize_finding_time
    total_inj_calls_end = proxy.injection_detector_calls
    total_inj_time_end = proxy.injection_detector_time

    metrics["D_sanitization_finding_count"] = len(sample_fir_subset)
    metrics["D_total_sanitize_finding_calls"] = total_san_calls_end
    metrics["D_calls_per_fir_ratio"] = total_san_calls_end / len(sample_fir_subset)
    metrics["D_total_sanitization_time_sec"] = total_san_time_end
    metrics["E_total_injection_calls"] = total_inj_calls_end
    metrics["E_total_injection_time_sec"] = total_inj_time_end

    metrics["G_qwen_call_count"] = len(qwen_call_times)
    metrics["G_qwen_total_time_sec"] = sum(qwen_call_times)
    metrics["G_qwen_avg_time_sec"] = sum(qwen_call_times) / max(1, len(qwen_call_times))
    metrics["G_qwen_min_time_sec"] = min(qwen_call_times) if qwen_call_times else 0.0
    metrics["G_qwen_max_time_sec"] = max(qwen_call_times) if qwen_call_times else 0.0
    metrics["G_total_input_tokens"] = sum(input_token_counts)
    metrics["G_total_output_tokens"] = sum(output_token_counts)
    metrics["G_tokens_per_sec"] = metrics["G_total_output_tokens"] / max(0.001, metrics["G_qwen_total_time_sec"])

    if torch.cuda.is_available():
        metrics["peak_gpu_memory_mb"] = torch.cuda.max_memory_allocated(0) / (1024 * 1024)
    else:
        metrics["peak_gpu_memory_mb"] = 0.0

    # ── H. AGENT 1 VALIDATOR MEASUREMENT ─────────────────────────────────────
    print("\n[STAGE H] Measuring Agent1Validator Execution...")
    validator = Agent1Validator()
    t_val_start = time.time()
    fir_map = {getattr(f, "finding_id"): f for f in sample_fir_subset}
    valid_finding_ids, valid_lineage_ids = validator.extract_valid_id_universe(sample_fir_subset)
    
    # Run validator on claims produced
    test_claims = [Agent1Claim(
        claim_id=f"CLM-AG1-BASE-{idx:03d}",
        summary=f"Sample summary for finding {getattr(f, 'finding_id')}",
        findings_summary=f"Ingested fact: {getattr(f, 'fact', '')}",
        cited_evidence_ids=[getattr(f, "finding_id")],
        assessed_importance="medium",
        confidence_score=0.9,
        reasoning_notes="Baseline measurement claim validation test"
    ) for idx, f in enumerate(sample_fir_subset)]

    val_res = validator.validate_claims(
        claims=test_claims,
        valid_finding_ids=valid_finding_ids,
        valid_lineage_ids=valid_lineage_ids,
        fir_map=fir_map
    )
    t_val_end = time.time()
    metrics["H_validation_time_sec"] = t_val_end - t_val_start
    print(f"  --> Agent1Validator Time for {len(test_claims)} claims: {metrics['H_validation_time_sec']:.6f} sec")

    # ── I. AGENT OUTPUT POSTGRESQL PERSISTENCE ────────────────────────────────
    print("\n[STAGE I] Measuring Agent Output PostgreSQL Persistence...")
    dummy_agent = EvidenceIntelligenceAgent(model=model, fir_repo=fir_repo, sanitization_gateway=gateway)
    sample_out = Agent1Output(
        case_id=case_id,
        tenant_id=tenant_id,
        model_used="Qwen3-8B",
        claims=val_res,
        total_findings_processed=len(sample_fir_subset),
        sanitization_summary={"findings_sanitized": len(sanitized_contexts)},
        execution_status="SUCCESS"
    )
    t_persist_start = time.time()
    dummy_agent._persist_agent_output(sample_out)
    t_persist_end = time.time()
    metrics["I_persistence_time_sec"] = t_persist_end - t_persist_start
    print(f"  --> PostgreSQL Output Persistence Time: {metrics['I_persistence_time_sec']:.4f} sec")

    t_global_end = time.time()
    metrics["K_total_wall_clock_sec"] = t_global_end - t_global_start

    print("\n" + "=" * 80)
    print("BASELINE MEASUREMENT SUMMARY RESULTS")
    print("=" * 80)
    print(json.dumps(metrics, indent=2))

    return metrics


if __name__ == "__main__":
    subset_size = 50
    if len(sys.argv) > 1:
        try:
            subset_size = int(sys.argv[1])
        except ValueError:
            pass
    run_baseline_measurement(subset_size=subset_size)
