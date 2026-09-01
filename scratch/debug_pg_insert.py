import sys
import os
from datetime import datetime, timezone
import psycopg2

sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))

from fir.schemas import FIRFinding, ReviewStatus
from fir.repository import FIRRepository
from config.settings import settings

def debug_insert():
    print(f"Connecting to Postgres at {settings.postgres_host}:{settings.postgres_port}...")
    try:
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=3
        )
        cur = conn.cursor()
        print("Connected! Attempting DDL execution...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS fir_findings (
                finding_id          TEXT PRIMARY KEY,
                case_id             TEXT NOT NULL,
                tenant_id           TEXT NOT NULL DEFAULT 'default',
                fact                TEXT NOT NULL,
                sanitized_fact      TEXT,
                confidence          FLOAT NOT NULL DEFAULT 1.0,
                severity            TEXT NOT NULL DEFAULT 'medium',
                mitre_mapping       TEXT,
                evidence_reference  TEXT[] NOT NULL DEFAULT '{}',
                source_artifact_id  TEXT,
                finding_fingerprint TEXT,
                review_status       TEXT NOT NULL DEFAULT 'pending_review',
                reviewed_by         TEXT,
                injection_flagged   BOOLEAN DEFAULT FALSE,
                injection_score     FLOAT DEFAULT 0.0,
                layer               TEXT NOT NULL DEFAULT 'unknown',
                timestamp           TIMESTAMPTZ DEFAULT NOW(),
                raw_data            JSONB DEFAULT '{}'
            );
            ALTER TABLE fir_findings DROP CONSTRAINT IF EXISTS fir_findings_case_id_fkey;
            ALTER TABLE fir_findings ALTER COLUMN case_id TYPE TEXT USING case_id::text;
            ALTER TABLE fir_findings ALTER COLUMN source_engine DROP NOT NULL;
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS sanitized_fact TEXT;
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS source_artifact_id TEXT;
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS finding_fingerprint TEXT;
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'pending_review';
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS reviewed_by TEXT;
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS injection_flagged BOOLEAN DEFAULT FALSE;
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS injection_score FLOAT DEFAULT 0.0;
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS layer TEXT DEFAULT 'unknown';
            ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ DEFAULT NOW();
        """)
        print("DDL Executed successfully!")
        
        fir_fnd = FIRFinding(
            finding_id="debug-test-01",
            case_id="CASE-DEBUG",
            tenant_id="tenant-debug",
            fact="Debug test finding",
            sanitized_fact="Debug test finding",
            confidence=0.9,
            severity="low",
            mitre_mapping="T1000",
            evidence_reference=["CORR-DEBUG"],
            source_artifact_id="art-debug",
            finding_fingerprint="fp-debug-01",
            review_status=ReviewStatus.PENDING_REVIEW,
            injection_flagged=False,
            injection_score=0.0,
            layer="endpoint",
            timestamp=datetime.now(timezone.utc)
        )
        
        review_st_str = fir_fnd.review_status.value if hasattr(fir_fnd.review_status, "value") else str(fir_fnd.review_status)
        cur.execute(
            """
            INSERT INTO fir_findings 
                (finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
                 evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
                 injection_flagged, injection_score, layer, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (finding_id) DO UPDATE SET
                fact = EXCLUDED.fact,
                sanitized_fact = EXCLUDED.sanitized_fact,
                confidence = EXCLUDED.confidence,
                severity = EXCLUDED.severity,
                mitre_mapping = EXCLUDED.mitre_mapping,
                evidence_reference = EXCLUDED.evidence_reference,
                source_artifact_id = EXCLUDED.source_artifact_id,
                finding_fingerprint = EXCLUDED.finding_fingerprint,
                review_status = EXCLUDED.review_status,
                reviewed_by = EXCLUDED.reviewed_by,
                injection_flagged = EXCLUDED.injection_flagged,
                injection_score = EXCLUDED.injection_score,
                layer = EXCLUDED.layer,
                timestamp = EXCLUDED.timestamp;
            """,
            (
                fir_fnd.finding_id,
                fir_fnd.case_id,
                fir_fnd.tenant_id,
                fir_fnd.fact,
                fir_fnd.sanitized_fact or fir_fnd.fact,
                fir_fnd.confidence,
                fir_fnd.severity,
                fir_fnd.mitre_mapping,
                fir_fnd.evidence_reference,
                fir_fnd.source_artifact_id,
                fir_fnd.finding_fingerprint,
                review_st_str,
                fir_fnd.reviewed_by,
                fir_fnd.injection_flagged,
                fir_fnd.injection_score,
                fir_fnd.layer,
                fir_fnd.timestamp,
            )
        )
        conn.commit()
        print("INSERT EXECUTED AND COMMITTED SUCCESSFULLY!")
        
        cur.execute("SELECT * FROM fir_findings WHERE finding_id = 'debug-test-01';")
        res = cur.fetchone()
        print("FETCHED ROW:", res)
        conn.close()

    except Exception as e:
        print("ERROR IN DEBUG INSERT:", type(e), e)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_insert()
