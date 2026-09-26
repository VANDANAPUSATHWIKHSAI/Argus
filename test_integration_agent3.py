import os
import json
from datetime import datetime, timezone

from fir.schemas import FIRFinding
from agents.agent3_attack_reconstruction.agent import AttackReconstructionAgent
from config.settings import settings
import psycopg2

def test_integration():
    case_id = "CASE-INT-3001"
    
    # 1. Create Mock FIR Findings (realistic)
    findings = [
        FIRFinding(
            finding_id="F-100",
            case_id=case_id,
            tenant_id="default",
            fact="Admin login from 10.0.0.5",
            evidence_reference=["E-100"],
            confidence=1.0,
            severity="medium",
            layer="event_log"
        ),
        FIRFinding(
            finding_id="F-101",
            case_id=case_id,
            tenant_id="default",
            fact="Malicious payload executed via powershell.exe bypass",
            evidence_reference=["E-101"],
            confidence=0.9,
            severity="high",
            layer="process_execution"
        )
    ]
    
    class RealFIRRepo:
        def get_by_case(self, tenant_id, case_id):
            return findings
    
    print("\n[+] 1. Initializing Neo4j Driver to verify Graph connection...")
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        driver.verify_connectivity()
        print("    Neo4j connection: OK")
        
        # Inject dummy graph data for Agent 3 candidate paths
        with driver.session() as session:
            session.run("""
                MERGE (a:Event {id: 'F-100', case_id: $case_id, description: 'Admin login'})
                MERGE (b:Event {id: 'F-101', case_id: $case_id, description: 'Powershell execution'})
                MERGE (a)-[:NEXT_EVENT]->(b)
            """, case_id=case_id)
        class MockNeo4jClient:
            def query(self, query, **kwargs):
                with driver.session() as session:
                    res = session.run(query, **kwargs)
                    return [dict(r) for r in res]
        neo4j_client = MockNeo4jClient()
    except Exception as e:
        print(f"    Neo4j connection FAILED: {e}")
        neo4j_client = None

    print("\n[+] 2. Running Agent 3 (with LLM Mock handling DB/Sanitization/Validation)...")
    agent = AttackReconstructionAgent(
        fir_repo=RealFIRRepo()
    )
    
    context = {
        "tenant_id": "default",
        "agent2_correlation": {"clusters": [{"events": ["F-100", "F-101"]}]},
        "neo4j_client": neo4j_client
    }
    
    output = agent.run(case_id=case_id, context=context)
    
    print(f"    Execution Status: {output.get('execution_status')}")
    print(f"    Error Message: {output.get('error_message')}")
    
    print("\n[+] 3. Verifying PostgreSQL Persistence...")
    try:
        conn = psycopg2.connect(settings.postgres_url)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, claim, execution_status, flags FROM agent_outputs WHERE case_id = %s AND agent_id = %s ORDER BY created_at DESC LIMIT 1",
            (case_id, "agent_3")
        )
        row = cur.fetchone()
        if row:
            print("    PostgreSQL Persistence: OK")
            print(f"    Persisted ID: {row[0]}")
            print(f"    Persisted Claim Text: {row[1]}")
            print(f"    Persisted Status: {row[2]}")
            
            flags = row[3]
            full_report = json.loads(flags.get("full_report", "{}"))
            print(f"    Re-parsed Timeline Length: {len(full_report.get('attack_timeline', []))}")
        else:
            print("    PostgreSQL Persistence: FAILED (No rows found)")
        conn.close()
    except Exception as e:
        print(f"    PostgreSQL error: {e}")

if __name__ == "__main__":
    test_integration()
