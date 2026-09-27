import json
import time
from typing import Dict, Any
import psycopg2

from fir.schemas import FIRFinding
from agents.agent3_attack_reconstruction.agent import AttackReconstructionAgent
from agents.agent3_attack_reconstruction.schemas import Agent3Output
from models.llm import OllamaWrapper
from config.settings import settings

def run_test():
    print("==================================================")
    print("REAL QWEN3 AGENT 3 TEST")
    print("==================================================")

    case_id = "CASE-CPU-TEST-001"
    tenant_id = "default"

    findings = [
        FIRFinding(
            finding_id="F001", case_id=case_id, tenant_id=tenant_id,
            fact="User opened a malicious document received through phishing email.",
            evidence_reference=["L001"], confidence=1.0, severity="high",
            layer="email", timestamp="2026-09-27T09:00:00Z",
            host="WORKSTATION-01", user="user", mitre_technique="T1566.001"
        ),
        FIRFinding(
            finding_id="F002", case_id=case_id, tenant_id=tenant_id,
            fact="WINWORD.EXE spawned powershell.exe.",
            evidence_reference=["L002"], confidence=1.0, severity="high",
            layer="process", timestamp="2026-09-27T09:05:00Z",
            host="WORKSTATION-01", user="user", process="powershell.exe", mitre_technique="T1059.001"
        ),
        FIRFinding(
            finding_id="F003", case_id=case_id, tenant_id=tenant_id,
            fact="PowerShell executed a suspicious encoded command.",
            evidence_reference=["L003"], confidence=1.0, severity="high",
            layer="process", timestamp="2026-09-27T09:06:00Z",
            host="WORKSTATION-01", user="user", process="powershell.exe", mitre_technique="T1059.001"
        ),
        FIRFinding(
            finding_id="F004", case_id=case_id, tenant_id=tenant_id,
            fact="WORKSTATION-01 made a suspicious outbound connection.",
            evidence_reference=["L004"], confidence=1.0, severity="high",
            layer="network", timestamp="2026-09-27T09:10:00Z",
            host="WORKSTATION-01", user="user", mitre_technique="T1071"
        ),
        FIRFinding(
            finding_id="F005", case_id=case_id, tenant_id=tenant_id,
            fact="WORKSTATION-01 initiated an SMB connection toward SERVER-01.",
            evidence_reference=["L005"], confidence=1.0, severity="high",
            layer="network", timestamp="2026-09-27T09:20:00Z",
            source_host="WORKSTATION-01", destination_host="SERVER-01", user="user", mitre_technique="T1021.002"
        )
    ]

    class RealFIRRepo:
        def get_by_case(self, tenant_id=None, case_id=None, **kwargs):
            return findings

    class MockNeo4j:
        def query(self, query, **kwargs):
            return [{"p": {"nodes": [{"id": f.finding_id} for f in findings], "rels": []}}]

    real_model = OllamaWrapper("qwen3:8b", "http://localhost:11434", allow_mock=False)
    agent = AttackReconstructionAgent(model=real_model, fir_repo=RealFIRRepo())
    
    # We will override the LLM's timeout internally or manually enforce it.
    # The OllamaWrapper might have a default timeout, let's wrap the call.
    
    context = {
        "tenant_id": tenant_id,
        "agent2_correlation": {"clusters": [{"events": [f.finding_id for f in findings]}]},
        "neo4j_client": MockNeo4j()
    }
    
    # Actually run Agent 3
    print("Sending to Agent 3 (timeout = 300s)...")
    start_time = time.time()
    
    # Note: requests to Ollama might hang if it takes too long, we assume OllamaWrapper handles it or we just let it run. 
    # For CPU-only, generation might be slow.
    
    output_dict = agent.run(case_id=case_id, context=context)
    
    duration = time.time() - start_time
    
    # If the generation didn't complete or threw a connection error
    if output_dict.get("execution_status") == "FAILED":
        print("AGENT 3 IMPLEMENTATION FAILED")
        print("Error:", output_dict.get("error_message"))
        return
        
    if duration > 300:
        print("REAL QWEN3 AGENT 3 TEST TIMED OUT")
        return
        
    print(f"\nCompleted in {duration:.2f} seconds\n")
    
    # 1. Raw Qwen3 response
    # The output_dict usually doesn't have the "raw" response in the final dict, 
    # but let's print what we have. It might be in 'raw_llm_response' if Agent 3 stores it.
    print("1. Raw Qwen3 response (if available):")
    print(output_dict.get("raw_response", "Not exposed by Agent 3"))
    
    print("\n2. Parsed Agent3Output (Dict):")
    print(json.dumps(output_dict, indent=2))
    
    print("\n3. infection_path:", output_dict.get("infection_path"))
    print("\n4. attack_timeline:", output_dict.get("attack_timeline"))
    print("\n5. attack_chain:", output_dict.get("attack_chain"))
    print("\n6. lateral_movement:", output_dict.get("lateral_movement"))
    print("\n7. missing_expected_events:", output_dict.get("missing_expected_events"))
    print("\n8. reconstruction_summary:", output_dict.get("reconstruction_summary"))
    print("\n9. overall_confidence:", output_dict.get("overall_confidence"))
    print("\n10. execution_status:", output_dict.get("execution_status"))
    
    # 11. evidence IDs used
    used_evidence = set()
    for stage in output_dict.get("attack_chain", []):
        used_evidence.update(stage.get("supporting_evidence", []))
    for timeline_event in output_dict.get("attack_timeline", []):
        used_evidence.update(timeline_event.get("supporting_evidence", []))
    for lm in output_dict.get("lateral_movement", []):
        used_evidence.update(lm.get("supporting_evidence", []))
        
    print("\n11. evidence IDs used:", list(used_evidence))
    
    valid_ids = {f.finding_id for f in findings}
    invalid_ids = used_evidence - valid_ids
    if invalid_ids:
        print("AGENT 3 IMPLEMENTATION FAILED")
        print(f"Invalid evidence IDs found: {invalid_ids}")
        return
        
    # Validation (Citation check implicit above if not done by validator)
    
    # PostgreSQL persistence readback
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=5
        )
        cur = conn.cursor()
        cur.execute("SELECT flags FROM agent_outputs WHERE case_id = %s AND agent_id = 'agent_3' ORDER BY created_at DESC LIMIT 1", (case_id,))
        row = cur.fetchone()
        conn.close()
        
        if not row:
            print("AGENT 3 IMPLEMENTATION FAILED")
            print("No persistence found in PostgreSQL")
            return
            
        print("\nPostgreSQL persistence: PASS")
    except Exception as e:
        print("AGENT 3 IMPLEMENTATION FAILED")
        print("PostgreSQL error:", str(e))
        return
        
    print("\nREAL QWEN3 AGENT 3 TEST PASSED")

if __name__ == "__main__":
    run_test()
